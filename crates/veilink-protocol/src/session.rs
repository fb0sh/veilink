//! The `VLP/1` session: multiplexed streams over one authenticated connection.
//!
//! # Structure
//!
//! A [`Session`] is a handle around a shared inner state plus two background tasks:
//!
//! * a **writer** task owns the send half. Every outbound message goes through a bounded channel,
//!   and the writer seals and transmits in queue order. Sealing inside the writer — rather than in
//!   the caller — is what makes the frame sequence number order match the wire order, which the
//!   receiver relies on for its replay check.
//! * a **reader** task owns the receive half. It authenticates each frame, dispatches it, and
//!   drives key-pool replenishment.
//!
//! # Streams
//!
//! A stream is a byte pipe with credit-based flow control in both directions. `STREAM_DATA` frames
//! consume the sender's credit; the receiver returns credit with `STREAM_WINDOW` once the
//! application has consumed about half a window. A sender that runs out of credit parks its writer
//! instead of buffering without bound, which is what keeps a slow reader from turning into memory
//! growth on the peer.
//!
//! # Failure isolation
//!
//! A malformed or hostile frame fails the *session*, because frame-level integrity is
//! all-or-nothing. A failure on one stream — a reset, a refused target, a stalled reader — only
//! affects that stream, and the connection cleanup path removes every stream when the session
//! ends, so nothing is left registered.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, Notify};
use tracing::{debug, trace, warn};

use veilink_crypto::{CryptoError, Direction, HandshakeKeys, Psk};

use crate::codec::{CodecError, PaddingPolicy, SessionCodec};
use crate::duplex::Duplex;
use crate::frame::{
    read_frame, write_authenticated_frame, write_handshake_frame, FrameHeader, RawFrame,
    MAX_PAYLOAD,
};
use crate::message::{Message, OpenStatus};

/// Largest payload carried in a single `STREAM_DATA` frame.
pub const MAX_STREAM_DATA: usize = 16 * 1024;

/// Default receive window advertised for a new stream.
pub const DEFAULT_WINDOW: u32 = 256 * 1024;

/// Smallest window that makes sense; below this, flow control would throttle every frame.
pub const MIN_WINDOW: u32 = 16 * 1024;

/// Which side of the connection this session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The local proxy client; it opens streams.
    Client,
    /// The relay server; it accepts streams.
    Server,
}

impl Role {
    /// Our sending direction.
    pub fn direction(self) -> Direction {
        match self {
            Role::Client => Direction::ClientToServer,
            Role::Server => Direction::ServerToClient,
        }
    }

    /// The first stream identifier this side allocates.
    fn first_stream_id(self) -> u32 {
        match self {
            Role::Client => 1,
            Role::Server => 2,
        }
    }
}

/// Tunables for a session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Maximum number of concurrently open streams.
    pub max_streams: usize,
    /// Receive window advertised for each new stream.
    pub initial_window: u32,
    /// Bound on the outbound message queue.
    pub outbound_queue: usize,
    /// How long `open_stream` waits for the peer's answer.
    pub open_timeout: Duration,
    /// How long the handshake may take.
    pub handshake_timeout: Duration,
    /// How long to wait for one-time keys when the peer's pool runs dry.
    pub key_wait_timeout: Duration,
    /// How long an idle session may stay open without any frame.
    pub idle_timeout: Duration,
    /// Target size of the local one-time key pool.
    pub key_pool_size: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            max_streams: 512,
            initial_window: DEFAULT_WINDOW,
            outbound_queue: 512,
            open_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
            key_wait_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            key_pool_size: veilink_crypto::DEFAULT_POOL_SIZE,
        }
    }
}

/// Errors raised by a session.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The underlying transport failed.
    #[error("transport error: {0}")]
    Io(#[from] io::Error),
    /// The cryptographic layer rejected something.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// The handshake failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The peer answered an `OPEN_STREAM` with a failure.
    #[error("the server refused stream {stream_id}: {status}{detail}")]
    OpenRefused {
        /// The stream that was refused.
        stream_id: u32,
        /// The status the server reported.
        status: &'static str,
        /// Optional detail.
        detail: String,
    },
    /// The peer never answered.
    #[error("timed out waiting for the peer")]
    Timeout,
    /// The session is closed.
    #[error("session is closed: {0}")]
    Closed(String),
    /// The stream limit was reached.
    #[error("the session already has {0} open streams")]
    TooManyStreams(usize),
    /// The peer violated the protocol.
    #[error("protocol violation: {0}")]
    Protocol(String),
}

/// Counters describing one session.
#[derive(Debug, Default)]
pub struct SessionStats {
    /// Frames sent.
    pub frames_sent: AtomicU64,
    /// Frames received.
    pub frames_received: AtomicU64,
    /// Frames rejected by the codec.
    pub frames_rejected: AtomicU64,
    /// Streams opened in total.
    pub streams_opened: AtomicU64,
    /// Streams currently open.
    pub streams_active: AtomicU64,
    /// Payload bytes written by the local application.
    pub bytes_up: AtomicU64,
    /// Payload bytes delivered to the local application.
    pub bytes_down: AtomicU64,
    /// Cover-traffic frames sent.
    pub cover_sent: AtomicU64,
    /// Cover-traffic bytes sent.
    pub cover_bytes: AtomicU64,
    /// One-time keys consumed.
    pub keys_consumed: AtomicU64,
    /// One-time keys published by the peer.
    pub keys_received: AtomicU64,
}

/// A point-in-time copy of [`SessionStats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionStatsSnapshot {
    /// See [`SessionStats::frames_sent`].
    pub frames_sent: u64,
    /// See [`SessionStats::frames_received`].
    pub frames_received: u64,
    /// See [`SessionStats::frames_rejected`].
    pub frames_rejected: u64,
    /// See [`SessionStats::streams_opened`].
    pub streams_opened: u64,
    /// See [`SessionStats::streams_active`].
    pub streams_active: u64,
    /// See [`SessionStats::bytes_up`].
    pub bytes_up: u64,
    /// See [`SessionStats::bytes_down`].
    pub bytes_down: u64,
    /// See [`SessionStats::cover_sent`].
    pub cover_sent: u64,
    /// See [`SessionStats::cover_bytes`].
    pub cover_bytes: u64,
    /// See [`SessionStats::keys_consumed`].
    pub keys_consumed: u64,
    /// See [`SessionStats::keys_received`].
    pub keys_received: u64,
}

impl SessionStats {
    /// Takes a snapshot.
    pub fn snapshot(&self) -> SessionStatsSnapshot {
        SessionStatsSnapshot {
            frames_sent: self.frames_sent.load(Ordering::Relaxed),
            frames_received: self.frames_received.load(Ordering::Relaxed),
            frames_rejected: self.frames_rejected.load(Ordering::Relaxed),
            streams_opened: self.streams_opened.load(Ordering::Relaxed),
            streams_active: self.streams_active.load(Ordering::Relaxed),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            cover_sent: self.cover_sent.load(Ordering::Relaxed),
            cover_bytes: self.cover_bytes.load(Ordering::Relaxed),
            keys_consumed: self.keys_consumed.load(Ordering::Relaxed),
            keys_received: self.keys_received.load(Ordering::Relaxed),
        }
    }
}

/// A stream waiting for the server runtime to connect to its target.
pub struct IncomingStream {
    /// The stream, already accepting data into its receive buffer.
    pub stream: VlpStream,
    /// Target host name, exactly as the client matched it against the whitelist.
    pub host: String,
    /// Target port.
    pub port: u16,
}

/// What the writer task sends.
enum Outbound {
    /// A message to seal and transmit.
    Message(Message),
    /// Stop after flushing everything queued.
    Shutdown,
}

/// Receive-side buffer for one stream.
struct RecvState {
    chunks: VecDeque<Vec<u8>>,
    /// Bytes of `chunks.front()` already consumed.
    front: usize,
    /// Bytes currently buffered.
    buffered: usize,
    /// Bytes delivered to the application since the last window update.
    delivered_since_grant: usize,
    /// The peer half-closed its side.
    fin: bool,
    /// The stream was reset.
    reset: Option<(u32, String)>,
}

impl RecvState {
    fn new() -> Self {
        RecvState {
            chunks: VecDeque::new(),
            front: 0,
            buffered: 0,
            delivered_since_grant: 0,
            fin: false,
            reset: None,
        }
    }
}

/// State shared between the session and every handle to one stream.
struct StreamShared {
    id: u32,
    /// Window we advertised: the peer may not exceed this many unconsumed bytes.
    window: u32,
    /// Bytes the peer still allows us to send.
    send_credit: Mutex<u64>,
    send_waker: Mutex<Option<Waker>>,
    recv: Mutex<RecvState>,
    recv_waker: Mutex<Option<Waker>>,
    /// Set once we have sent `STREAM_FIN`.
    local_finished: AtomicBool,
    /// Set once the peer's `STREAM_FIN` has been observed.
    remote_finished: AtomicBool,
}

impl StreamShared {
    fn new(id: u32, window: u32, initial_credit: u64) -> Self {
        StreamShared {
            id,
            window,
            send_credit: Mutex::new(initial_credit),
            send_waker: Mutex::new(None),
            recv: Mutex::new(RecvState::new()),
            recv_waker: Mutex::new(None),
            local_finished: AtomicBool::new(false),
            remote_finished: AtomicBool::new(false),
        }
    }

    fn wake_reader(&self) {
        if let Ok(mut slot) = self.recv_waker.lock() {
            if let Some(waker) = slot.take() {
                waker.wake();
            }
        }
    }

    fn wake_writer(&self) {
        if let Ok(mut slot) = self.send_waker.lock() {
            if let Some(waker) = slot.take() {
                waker.wake();
            }
        }
    }
}

/// Session-wide state shared by the handle and both tasks.
struct SessionInner {
    codec: Mutex<SessionCodec>,
    outbound: mpsc::Sender<Outbound>,
    streams: Mutex<HashMap<u32, Arc<StreamShared>>>,
    open_waiters: Mutex<HashMap<u32, oneshot::Sender<(OpenStatus, u32)>>>,
    incoming: Option<mpsc::Sender<IncomingStream>>,
    /// Handed out exactly once to the server runtime.
    incoming_receiver: Mutex<Option<mpsc::Receiver<IncomingStream>>>,
    next_stream_id: AtomicU32,
    next_ping: AtomicU64,
    ping_waiters: Mutex<HashMap<u64, oneshot::Sender<()>>>,
    /// Woken whenever the peer publishes one-time keys.
    keys_available: Notify,
    /// Woken when the session closes, so supervisors do not have to poll.
    closed_notify: Notify,
    /// Woken whenever the outbound queue has room again.
    capacity: Mutex<Vec<Waker>>,
    closed: AtomicBool,
    close_reason: Mutex<Option<String>>,
    /// The server's authenticated long-term identity, for the client's pin check.
    server_identity: Option<[u8; 32]>,
    stats: SessionStats,
    config: SessionConfig,
}

impl SessionInner {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn close(&self, reason: impl Into<String>) {
        let reason = reason.into();
        if !self.closed.swap(true, Ordering::SeqCst) {
            debug!(reason = %reason, "session closed");
            if let Ok(mut slot) = self.close_reason.lock() {
                *slot = Some(reason);
            }
            // Wake everyone so nothing is left parked forever.
            if let Ok(mut wakers) = self.capacity.lock() {
                for waker in wakers.drain(..) {
                    waker.wake();
                }
            }
            self.keys_available.notify_waiters();
            self.closed_notify.notify_waiters();
            self.fail_all_streams("session closed");
        }
    }

    fn fail_all_streams(&self, reason: &str) {
        let streams: Vec<Arc<StreamShared>> = match self.streams.lock() {
            Ok(mut map) => map.drain().map(|(_, v)| v).collect(),
            Err(_) => Vec::new(),
        };
        for stream in streams {
            if let Ok(mut recv) = stream.recv.lock() {
                if recv.reset.is_none() {
                    recv.reset = Some((1, reason.to_string()));
                }
            }
            stream.remote_finished.store(true, Ordering::Relaxed);
            stream.wake_reader();
            stream.wake_writer();
        }
        if let Ok(mut waiters) = self.open_waiters.lock() {
            waiters.clear();
        }
        if let Ok(mut pings) = self.ping_waiters.lock() {
            pings.clear();
        }
        self.stats.streams_active.store(0, Ordering::Relaxed);
    }

    fn wake_capacity(&self) {
        if let Ok(mut wakers) = self.capacity.lock() {
            for waker in wakers.drain(..) {
                waker.wake();
            }
        }
    }

    fn enqueue(&self, message: Message) -> Result<(), SessionError> {
        if self.is_closed() {
            return Err(SessionError::Closed(self.reason()));
        }
        self.outbound
            .try_send(Outbound::Message(message))
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => {
                    SessionError::Protocol("outbound queue is full".to_string())
                }
                mpsc::error::TrySendError::Closed(_) => SessionError::Closed(self.reason()),
            })
    }

    fn reason(&self) -> String {
        self.close_reason
            .lock()
            .ok()
            .and_then(|r| r.clone())
            .unwrap_or_else(|| "closed".to_string())
    }

    fn register_stream(&self, stream: Arc<StreamShared>) -> Result<(), SessionError> {
        let mut streams = self
            .streams
            .lock()
            .map_err(|_| SessionError::Protocol("stream table is poisoned".to_string()))?;
        if streams.len() >= self.config.max_streams {
            return Err(SessionError::TooManyStreams(streams.len()));
        }
        streams.insert(stream.id, stream);
        self.stats.streams_active.fetch_add(1, Ordering::Relaxed);
        self.stats.streams_opened.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn remove_stream(&self, id: u32) {
        if let Ok(mut streams) = self.streams.lock() {
            if streams.remove(&id).is_some() {
                self.stats.streams_active.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    fn stream(&self, id: u32) -> Option<Arc<StreamShared>> {
        self.streams.lock().ok()?.get(&id).cloned()
    }

    fn allocate_stream_id(&self) -> u32 {
        self.next_stream_id.fetch_add(2, Ordering::Relaxed)
    }
}

/// A `VLP/1` session handle. Cheap to clone.
#[derive(Clone)]
pub struct Session {
    inner: Arc<SessionInner>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("session_id", &format!("{:#x}", self.session_id()))
            .field("closed", &self.is_closed())
            .field("streams", &self.open_streams())
            .finish()
    }
}

impl Session {
    /// The session identifier.
    pub fn session_id(&self) -> u64 {
        self.inner
            .codec
            .lock()
            .map(|c| c.session_id())
            .unwrap_or_default()
    }

    /// The server's authenticated long-term identity, as advertised in its handshake message.
    ///
    /// The value is authenticated because the whole `SERVER_HELLO` is covered by the transcript
    /// that the confirmation MAC protects. A client can pin it to detect a swapped server.
    pub fn server_identity(&self) -> Option<[u8; 32]> {
        self.inner.server_identity
    }

    /// True when the session has been closed.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Why the session closed, if it has.
    pub fn close_reason(&self) -> Option<String> {
        self.inner.close_reason.lock().ok().and_then(|r| r.clone())
    }

    /// Number of currently open streams.
    pub fn open_streams(&self) -> usize {
        self.inner
            .streams
            .lock()
            .map(|s| s.len())
            .unwrap_or_default()
    }

    /// Session counters.
    pub fn stats(&self) -> SessionStatsSnapshot {
        self.inner.stats.snapshot()
    }

    /// The number of unconsumed one-time keys held locally.
    pub fn local_keys(&self) -> usize {
        self.inner
            .codec
            .lock()
            .map(|c| c.local_keys_available())
            .unwrap_or_default()
    }

    /// The number of unused peer keys available for sealing.
    pub fn peer_keys(&self) -> usize {
        self.inner
            .codec
            .lock()
            .map(|c| c.peer_keys_available())
            .unwrap_or_default()
    }

    /// Opens a stream to `host:port` through the server.
    ///
    /// The host name is transmitted verbatim inside an encrypted frame; the client never resolves
    /// it. The call returns once the server has confirmed that the outbound connection exists.
    pub async fn open_stream(&self, host: &str, port: u16) -> Result<VlpStream, SessionError> {
        if self.inner.is_closed() {
            return Err(SessionError::Closed(self.inner.reason()));
        }
        let id = self.inner.allocate_stream_id();
        let window = self.inner.config.initial_window.max(MIN_WINDOW);
        // Credit starts at zero: the server grants it in `OPEN_RESULT`.
        let shared = Arc::new(StreamShared::new(id, window, 0));
        self.inner.register_stream(shared.clone())?;

        let (tx, rx) = oneshot::channel();
        if let Ok(mut waiters) = self.inner.open_waiters.lock() {
            waiters.insert(id, tx);
        }

        if let Err(e) = self.inner.enqueue(Message::OpenStream {
            stream_id: id,
            host: host.to_string(),
            port,
            kind: crate::message::StreamKind::Tcp,
            initial_window: window,
        }) {
            self.inner.remove_stream(id);
            return Err(e);
        }

        match tokio::time::timeout(self.inner.config.open_timeout, rx).await {
            Ok(Ok((OpenStatus::Ok, credit))) => {
                *shared
                    .send_credit
                    .lock()
                    .map_err(|_| SessionError::Protocol("credit lock poisoned".into()))? =
                    credit as u64;
                Ok(VlpStream {
                    shared,
                    session: self.clone(),
                })
            }
            Ok(Ok((status, _))) => {
                self.inner.remove_stream(id);
                Err(SessionError::OpenRefused {
                    stream_id: id,
                    status: status.name(),
                    detail: String::new(),
                })
            }
            Ok(Err(_)) => {
                self.inner.remove_stream(id);
                Err(SessionError::Closed(self.inner.reason()))
            }
            Err(_) => {
                self.inner.remove_stream(id);
                if let Ok(mut waiters) = self.inner.open_waiters.lock() {
                    waiters.remove(&id);
                }
                Err(SessionError::Timeout)
            }
        }
    }

    /// Answers an `OPEN_STREAM`.
    ///
    /// The server runtime calls this after its egress attempt, then splices the stream to the
    /// target socket when the status is [`OpenStatus::Ok`].
    pub fn respond_open(
        &self,
        stream_id: u32,
        status: OpenStatus,
        detail: &str,
    ) -> Result<(), SessionError> {
        let window = self.inner.config.initial_window.max(MIN_WINDOW);
        let result = self.inner.enqueue(Message::OpenResult {
            stream_id,
            status,
            detail: detail.to_string(),
            initial_window: if status == OpenStatus::Ok { window } else { 0 },
        });
        if status == OpenStatus::Ok {
            if let Some(shared) = self.inner.stream(stream_id) {
                if let Ok(mut credit) = shared.send_credit.lock() {
                    *credit = window as u64;
                }
                shared.wake_writer();
            }
        } else {
            self.inner.remove_stream(stream_id);
        }
        result
    }

    /// Sends an authenticated cover frame.
    ///
    /// Cover traffic uses exactly the same per-frame cryptography as real data, so an observer
    /// cannot tell the two apart by construction — only by the fact that a cover frame produces no
    /// response.
    pub fn send_cover(&self, payload_len: usize) -> Result<(), SessionError> {
        let capped = payload_len.min(MAX_PAYLOAD);
        if self.inner.is_closed() {
            return Err(SessionError::Closed(self.inner.reason()));
        }
        self.inner.enqueue(Message::Cover {
            payload: vec![0u8; capped],
        })?;
        self.inner.stats.cover_sent.fetch_add(1, Ordering::Relaxed);
        self.inner
            .stats
            .cover_bytes
            .fetch_add(capped as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Resolves once the session has closed, for any reason.
    ///
    /// Supervisors use this instead of polling so that a reconnect happens promptly.
    pub async fn wait_closed(&self) {
        // Register before checking so a closure between the check and the wait cannot be missed.
        let notified = self.inner.closed_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.inner.is_closed() {
            return;
        }
        notified.await;
    }

    /// Sends a keepalive and waits for the reply.
    pub async fn ping(&self) -> Result<Duration, SessionError> {
        if self.inner.is_closed() {
            return Err(SessionError::Closed(self.inner.reason()));
        }
        let nonce = self.inner.next_ping.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        if let Ok(mut waiters) = self.inner.ping_waiters.lock() {
            waiters.insert(nonce, tx);
        }
        let started = Instant::now();
        self.inner.enqueue(Message::Ping { nonce })?;
        match tokio::time::timeout(self.inner.config.open_timeout, rx).await {
            Ok(Ok(())) => Ok(started.elapsed()),
            Ok(Err(_)) => Err(SessionError::Closed(self.inner.reason())),
            Err(_) => {
                if let Ok(mut waiters) = self.inner.ping_waiters.lock() {
                    waiters.remove(&nonce);
                }
                Err(SessionError::Timeout)
            }
        }
    }

    /// Aborts a stream from outside its own handle.
    ///
    /// The server runtime uses this when a splice fails after `OPEN_RESULT` has already been sent,
    /// so that the client sees a reset instead of a silent end of stream.
    pub fn reset_stream(&self, stream_id: u32, code: u32, reason: &str) {
        let _ = self.inner.enqueue(Message::StreamReset {
            stream_id,
            code,
            reason: reason.to_string(),
        });
        if let Some(shared) = self.inner.stream(stream_id) {
            if let Ok(mut recv) = shared.recv.lock() {
                recv.reset = Some((code, reason.to_string()));
            }
            shared.wake_reader();
            shared.wake_writer();
        }
        self.inner.remove_stream(stream_id);
    }

    /// Closes the session gracefully: sends `GOAWAY` and stops both tasks.
    pub async fn close(&self, reason: &str) {
        if self.inner.is_closed() {
            return;
        }
        let _ = self.inner.enqueue(Message::GoAway {
            code: 0,
            reason: reason.to_string(),
        });
        // Give the writer a moment to flush the GOAWAY before tearing down.
        tokio::time::sleep(Duration::from_millis(50)).await;
        self.inner.close(reason);
        let _ = self.inner.outbound.try_send(Outbound::Shutdown);
    }

    /// The stream receiver used by the server runtime.
    pub fn incoming_streams(&self) -> Option<mpsc::Receiver<IncomingStream>> {
        // The receiver is handed out exactly once, at construction time.
        self.inner
            .incoming_receiver
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
    }

    /// A handle on the shared configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.inner.config
    }
}

/// Establishes a session over `duplex` and starts its background tasks.
///
/// `exporter` is the TLS exporter of the underlying session. It is the value that binds the
/// authentication to this specific TLS connection, so it must come from the transport and must not
/// be defaulted or reused.
pub async fn start_session<D>(
    duplex: D,
    role: Role,
    psk: &Psk,
    exporter: [u8; 32],
    identity: [u8; 32],
    config: SessionConfig,
    padding: Arc<dyn PaddingPolicy>,
) -> Result<Session, SessionError>
where
    D: Duplex + 'static,
{
    let handshake = tokio::time::timeout(
        config.handshake_timeout,
        run_handshake(duplex, role, psk, exporter, identity),
    )
    .await
    .map_err(|_| SessionError::Timeout)??;

    let (keys, duplex, server_identity) = handshake;
    build_session(duplex, role, keys, server_identity, config, padding).await
}

/// Runs the handshake over a duplex stream and returns the session keys with the stream.
async fn run_handshake<D>(
    mut duplex: D,
    role: Role,
    psk: &Psk,
    exporter: [u8; 32],
    identity: [u8; 32],
) -> Result<(HandshakeKeys, D, Option<[u8; 32]>), SessionError>
where
    D: Duplex,
{
    use veilink_crypto::{ClientHandshake, ServerHandshake};

    match role {
        Role::Client => {
            let (mut handshake, hello) = ClientHandshake::start(psk)?;
            write_handshake_frame(&mut duplex, &hello).await?;

            let frame = read_frame(&mut duplex, true).await?;
            let server_hello = match frame {
                RawFrame::Handshake(bytes) => bytes,
                RawFrame::Authenticated { .. } => {
                    return Err(SessionError::Protocol(
                        "server sent an authenticated frame before the handshake completed"
                            .to_string(),
                    ))
                }
            };
            handshake.on_server_hello(&server_hello)?;
            let confirm = handshake.client_confirm(exporter)?;
            write_handshake_frame(&mut duplex, &confirm).await?;

            let frame = read_frame(&mut duplex, true).await?;
            let server_confirm = match frame {
                RawFrame::Handshake(bytes) => bytes,
                RawFrame::Authenticated { .. } => {
                    return Err(SessionError::Protocol(
                        "server sent an authenticated frame before authenticating the client"
                            .to_string(),
                    ))
                }
            };
            let server_identity = handshake.server_identity();
            let keys = handshake.verify_server_confirm(&server_confirm)?;
            Ok((keys, duplex, server_identity))
        }
        Role::Server => {
            let mut handshake = ServerHandshake::new(psk, config_pool_hint(), identity);
            let frame = read_frame(&mut duplex, true).await?;
            let client_hello = match frame {
                RawFrame::Handshake(bytes) => bytes,
                RawFrame::Authenticated { .. } => {
                    return Err(SessionError::Protocol(
                        "client sent an authenticated frame before the handshake".to_string(),
                    ))
                }
            };
            let server_hello = handshake.on_client_hello(&client_hello)?;
            write_handshake_frame(&mut duplex, &server_hello).await?;

            let frame = read_frame(&mut duplex, true).await?;
            let client_confirm = match frame {
                RawFrame::Handshake(bytes) => bytes,
                RawFrame::Authenticated { .. } => {
                    return Err(SessionError::Protocol(
                        "client sent an authenticated frame before confirming".to_string(),
                    ))
                }
            };
            let server_confirm = handshake.verify_client_confirm(&client_confirm, exporter)?;
            write_handshake_frame(&mut duplex, &server_confirm).await?;

            let keys = handshake
                .keys()
                .ok_or_else(|| SessionError::Protocol("handshake produced no keys".to_string()))?
                .clone();
            // The server knows its own identity; reporting it keeps both roles symmetric.
            Ok((keys, duplex, Some(identity)))
        }
    }
}

fn config_pool_hint() -> u16 {
    veilink_crypto::DEFAULT_POOL_SIZE as u16
}

async fn build_session<D>(
    duplex: D,
    role: Role,
    keys: HandshakeKeys,
    server_identity: Option<[u8; 32]>,
    config: SessionConfig,
    padding: Arc<dyn PaddingPolicy>,
) -> Result<Session, SessionError>
where
    D: Duplex + 'static,
{
    let codec = SessionCodec::new(&keys, role.direction(), padding, config.key_pool_size);
    let (outbound_tx, outbound_rx) = mpsc::channel(config.outbound_queue.max(8));
    let (incoming_tx, incoming_rx) = mpsc::channel(config.max_streams.max(8));

    let (reader_half, writer_half) = tokio::io::split(duplex);

    let inner = Arc::new(SessionInner {
        codec: Mutex::new(codec),
        outbound: outbound_tx,
        streams: Mutex::new(HashMap::new()),
        open_waiters: Mutex::new(HashMap::new()),
        incoming: if role == Role::Server {
            Some(incoming_tx)
        } else {
            None
        },
        incoming_receiver: Mutex::new(if role == Role::Server {
            Some(incoming_rx)
        } else {
            None
        }),
        next_stream_id: AtomicU32::new(role.first_stream_id()),
        next_ping: AtomicU64::new(1),
        ping_waiters: Mutex::new(HashMap::new()),
        keys_available: Notify::new(),
        closed_notify: Notify::new(),
        capacity: Mutex::new(Vec::new()),
        closed: AtomicBool::new(false),
        close_reason: Mutex::new(None),
        server_identity,
        stats: SessionStats::default(),
        config,
    });

    // Publish one-time keys immediately so the peer can start sending.
    {
        let mut codec = inner
            .codec
            .lock()
            .map_err(|_| SessionError::Protocol("codec lock poisoned".to_string()))?;
        if let Some(offer) = codec.initial_key_offer()? {
            let _ = inner.outbound.try_send(Outbound::Message(offer));
        }
    }

    let session = Session {
        inner: inner.clone(),
    };

    tokio::spawn(writer_task(inner.clone(), writer_half, outbound_rx));
    tokio::spawn(reader_task(inner.clone(), reader_half));

    Ok(session)
}

async fn writer_task<W>(
    inner: Arc<SessionInner>,
    mut writer: W,
    mut receiver: mpsc::Receiver<Outbound>,
) where
    W: AsyncWrite + Unpin,
{
    while let Some(item) = receiver.recv().await {
        match item {
            Outbound::Shutdown => break,
            Outbound::Message(message) => {
                if let Err(error) = write_one(&inner, &mut writer, &message).await {
                    warn!(error = %error, "session writer stopped");
                    inner.close(error.to_string());
                    break;
                }
                inner.wake_capacity();
            }
        }
    }
    let _ = AsyncWriteExt::shutdown(&mut writer).await;
}

/// Seals and transmits one message, waiting for one-time keys if the peer has not published any.
async fn write_one<W>(
    inner: &Arc<SessionInner>,
    writer: &mut W,
    message: &Message,
) -> Result<(), SessionError>
where
    W: AsyncWrite + Unpin,
{
    let deadline = Instant::now() + inner.config.key_wait_timeout;
    loop {
        // Register interest before trying, so a key offer that arrives between the attempt and the
        // wait cannot be lost.
        let notified = inner.keys_available.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();

        let sealed = {
            let mut codec = inner
                .codec
                .lock()
                .map_err(|_| SessionError::Protocol("codec lock poisoned".to_string()))?;
            let attempt = if message.is_control() {
                codec.seal_control(message).map(Some)
            } else {
                codec.seal_application(message).map(Some)
            };
            match attempt {
                Ok(bytes) => Ok(bytes),
                // The peer's one-time pool is empty. Ask for more keys inside the same lock, then
                // wait outside it: taking the lock again here would deadlock.
                Err(CodecError::NoPeerKey) => {
                    let ack = codec.key_ack();
                    drop(codec);
                    let _ = inner.outbound.try_send(Outbound::Message(ack));
                    Ok(None)
                }
                Err(e) => Err(e),
            }
        }
        .map_err(SessionError::Codec)?;

        let Some(bytes) = sealed else {
            if inner.is_closed() {
                return Err(SessionError::Closed(inner.reason()));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SessionError::Protocol(
                    "the peer did not publish one-time keys in time".to_string(),
                ));
            }
            if tokio::time::timeout(remaining, notified).await.is_err() {
                return Err(SessionError::Protocol(
                    "the peer did not publish one-time keys in time".to_string(),
                ));
            }
            continue;
        };

        let header = FrameHeader::decode(&bytes[..crate::frame::AUTHENTICATED_HEADER_LEN])
            .map_err(|e| SessionError::Protocol(e.to_string()))?;
        let body = &bytes[crate::frame::AUTHENTICATED_HEADER_LEN..];
        write_authenticated_frame(writer, &header, body).await?;
        inner.stats.frames_sent.fetch_add(1, Ordering::Relaxed);
        trace!(frame_bytes = bytes.len(), "frame sent");
        return Ok(());
    }
}

async fn reader_task<R>(inner: Arc<SessionInner>, mut reader: R)
where
    R: AsyncRead + Unpin,
{
    loop {
        let frame =
            match tokio::time::timeout(inner.config.idle_timeout, read_frame(&mut reader, false))
                .await
            {
                Err(_) => {
                    inner.close("idle timeout");
                    break;
                }
                Ok(Err(error)) => {
                    // A clean end of stream is not an error worth logging loudly.
                    if error.kind() != io::ErrorKind::UnexpectedEof
                        && error.kind() != io::ErrorKind::ConnectionReset
                    {
                        debug!(error = %error, "session reader stopped");
                    }
                    inner.close(error.to_string());
                    break;
                }
                Ok(Ok(frame)) => frame,
            };

        let (header, body) = match frame {
            RawFrame::Authenticated { header, body } => (header, body),
            RawFrame::Handshake(_) => {
                warn!("cleartext handshake frame received on an established session");
                inner.stats.frames_rejected.fetch_add(1, Ordering::Relaxed);
                inner.close("cleartext frame after handshake");
                break;
            }
        };

        let (opened, consumed) = {
            let mut codec = match inner.codec.lock() {
                Ok(codec) => codec,
                Err(_) => break,
            };
            let before = codec.local_keys_consumed();
            let result = if header.epoch == 0 {
                codec.open_control(&header, &body)
            } else {
                codec.open_application(&header, &body)
            };
            (result, codec.local_keys_consumed().saturating_sub(before))
        };
        if consumed > 0 {
            inner
                .stats
                .keys_consumed
                .fetch_add(consumed, Ordering::Relaxed);
        }

        let message = match opened {
            Ok(message) => message,
            Err(error) => {
                inner.stats.frames_rejected.fetch_add(1, Ordering::Relaxed);
                warn!(error = %error, "rejecting frame");
                // A frame that fails authentication is fatal for the session: the connection is
                // no longer trustworthy and there is no partial-recovery state to fall back to.
                inner.close(format!("frame rejected: {error}"));
                break;
            }
        };

        inner.stats.frames_received.fetch_add(1, Ordering::Relaxed);
        if dispatch(&inner, message).await.is_err() {
            break;
        }

        // Keep the local key pool topped up; the peer's traffic drives replenishment.
        let offer = {
            match inner.codec.lock() {
                Ok(mut codec) => codec.maybe_offer_keys().ok().flatten(),
                Err(_) => None,
            }
        };
        if let Some(offer) = offer {
            let _ = inner.outbound.try_send(Outbound::Message(offer));
        }
    }
    inner.close("reader stopped");
}

async fn dispatch(inner: &Arc<SessionInner>, message: Message) -> Result<(), ()> {
    match message {
        Message::KeyOffer { keys } => {
            let count = keys.len();
            let accepted = {
                match inner.codec.lock() {
                    Ok(mut codec) => codec.handle_key_offer(&keys),
                    Err(_) => return Err(()),
                }
            };
            match accepted {
                Ok(added) => {
                    inner
                        .stats
                        .keys_received
                        .fetch_add(added as u64, Ordering::Relaxed);
                    trace!(offered = count, accepted = added, "received one-time keys");
                    inner.keys_available.notify_waiters();
                }
                Err(error) => {
                    warn!(error = %error, "rejecting a key offer");
                    inner.close(format!("bad key offer: {error}"));
                    return Err(());
                }
            }
        }
        Message::KeyAck { request_more, .. } => {
            if request_more {
                let offer = match inner.codec.lock() {
                    Ok(mut codec) => codec.initial_key_offer().ok().flatten(),
                    Err(_) => None,
                };
                if let Some(offer) = offer {
                    let _ = inner.outbound.try_send(Outbound::Message(offer));
                }
            }
        }
        Message::Ping { nonce } => {
            let _ = inner
                .outbound
                .try_send(Outbound::Message(Message::Pong { nonce }));
        }
        Message::Pong { nonce } => {
            if let Ok(mut waiters) = inner.ping_waiters.lock() {
                if let Some(tx) = waiters.remove(&nonce) {
                    let _ = tx.send(());
                }
            }
        }
        Message::GoAway { code, reason } => {
            debug!(code, reason = %reason, "peer closed the session");
            inner.close(format!("peer sent GOAWAY ({code}): {reason}"));
            return Err(());
        }
        Message::Error { code, message } => {
            warn!(code, message = %message, "peer reported an error");
            inner.close(format!("peer error ({code}): {message}"));
            return Err(());
        }
        Message::OpenStream {
            stream_id,
            host,
            port,
            initial_window,
            ..
        } => {
            let Some(incoming) = inner.incoming.clone() else {
                // A client must never accept a stream from a server.
                inner.close("client received OPEN_STREAM");
                return Err(());
            };
            if host.is_empty() {
                let _ = inner
                    .outbound
                    .try_send(Outbound::Message(Message::OpenResult {
                        stream_id,
                        status: OpenStatus::BadRequest,
                        detail: "empty host".to_string(),
                        initial_window: 0,
                    }));
                return Ok(());
            }
            let window = inner.config.initial_window.max(MIN_WINDOW);
            let shared = Arc::new(StreamShared::new(stream_id, window, initial_window as u64));
            if let Err(error) = inner.register_stream(shared.clone()) {
                let _ = inner
                    .outbound
                    .try_send(Outbound::Message(Message::OpenResult {
                        stream_id,
                        status: OpenStatus::TooManyStreams,
                        detail: error.to_string(),
                        initial_window: 0,
                    }));
                return Ok(());
            }
            let stream = VlpStream {
                shared,
                session: Session {
                    inner: inner.clone(),
                },
            };
            if incoming
                .send(IncomingStream { stream, host, port })
                .await
                .is_err()
            {
                // The server runtime is gone; the session is over.
                inner.close("server runtime stopped accepting streams");
                return Err(());
            }
        }
        Message::OpenResult {
            stream_id,
            status,
            detail: _,
            initial_window,
        } => {
            let waiter = inner
                .open_waiters
                .lock()
                .ok()
                .and_then(|mut w| w.remove(&stream_id));
            if let Some(tx) = waiter {
                let _ = tx.send((status, initial_window));
            } else {
                trace!(stream_id, "OPEN_RESULT for an unknown stream");
            }
        }
        Message::StreamData { stream_id, data } => {
            let Some(shared) = inner.stream(stream_id) else {
                // Data for a stream we already dropped: ignore it rather than failing the session.
                trace!(stream_id, "data for an unknown stream");
                return Ok(());
            };
            let overflow = {
                let mut recv = match shared.recv.lock() {
                    Ok(recv) => recv,
                    Err(_) => return Err(()),
                };
                recv.buffered += data.len();
                let overflow = recv.buffered as u32 > shared.window;
                recv.chunks.push_back(data);
                overflow
            };
            if overflow {
                // The peer sent more than its credit allowed. Reset the stream; keep the session,
                // since other streams are unaffected.
                warn!(stream_id, "peer exceeded the flow-control window");
                let _ = inner
                    .outbound
                    .try_send(Outbound::Message(Message::StreamReset {
                        stream_id,
                        code: 3,
                        reason: "flow control window exceeded".to_string(),
                    }));
                inner.remove_stream(stream_id);
                if let Ok(mut recv) = shared.recv.lock() {
                    recv.reset = Some((3, "flow control window exceeded".to_string()));
                    recv.chunks.clear();
                    recv.buffered = 0;
                }
                shared.wake_reader();
                return Ok(());
            }
            shared.wake_reader();
        }
        Message::StreamWindow { stream_id, credit } => {
            if let Some(shared) = inner.stream(stream_id) {
                if let Ok(mut send_credit) = shared.send_credit.lock() {
                    *send_credit = send_credit.saturating_add(credit as u64);
                }
                shared.wake_writer();
            }
        }
        Message::StreamFin { stream_id } => {
            if let Some(shared) = inner.stream(stream_id) {
                shared.remote_finished.store(true, Ordering::Relaxed);
                if let Ok(mut recv) = shared.recv.lock() {
                    recv.fin = true;
                }
                shared.wake_reader();
            }
        }
        Message::StreamReset {
            stream_id, reason, ..
        } => {
            if let Some(shared) = inner.stream(stream_id) {
                if let Ok(mut recv) = shared.recv.lock() {
                    recv.reset = Some((2, reason));
                }
                shared.remote_finished.store(true, Ordering::Relaxed);
                shared.wake_reader();
                shared.wake_writer();
            }
            inner.remove_stream(stream_id);
        }
        Message::Cover { payload } => {
            trace!(bytes = payload.len(), "discarding cover traffic");
        }
    }
    Ok(())
}

/// A bidirectional byte stream carried inside a `VLP/1` session.
pub struct VlpStream {
    shared: Arc<StreamShared>,
    session: Session,
}

impl std::fmt::Debug for VlpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlpStream")
            .field("id", &self.shared.id)
            .field("window", &self.shared.window)
            .finish()
    }
}

impl VlpStream {
    /// The stream identifier. Identifiers are allocated by the peer and are only unique within a
    /// session.
    pub fn id(&self) -> u32 {
        self.shared.id
    }

    /// Bytes the peer still allows us to send.
    pub fn send_credit(&self) -> u64 {
        self.shared.send_credit.lock().map(|c| *c).unwrap_or(0)
    }

    /// Bytes sitting in the receive buffer.
    pub fn buffered(&self) -> usize {
        self.shared.recv.lock().map(|r| r.buffered).unwrap_or(0)
    }

    /// Resets the stream with a reason.
    pub fn reset(&self, code: u32, reason: &str) {
        let _ = self.session.inner.enqueue(Message::StreamReset {
            stream_id: self.shared.id,
            code,
            reason: reason.to_string(),
        });
        self.session.inner.remove_stream(self.shared.id);
        if let Ok(mut recv) = self.shared.recv.lock() {
            recv.reset = Some((code, reason.to_string()));
        }
        self.shared.wake_reader();
        self.shared.wake_writer();
    }

    /// True when the peer has half-closed its side.
    pub fn peer_finished(&self) -> bool {
        self.shared.remote_finished.load(Ordering::Relaxed)
    }
}

impl AsyncRead for VlpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let shared = &self.shared;
        let mut recv = match shared.recv.lock() {
            Ok(recv) => recv,
            Err(_) => return Poll::Ready(Err(io::Error::other("stream state is poisoned"))),
        };

        if let Some((code, reason)) = &recv.reset {
            let error = io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("stream reset ({code}): {reason}"),
            );
            return Poll::Ready(Err(error));
        }

        let mut copied = 0usize;
        while buf.remaining() > 0 {
            let (front_len, front_start) = match recv.chunks.front() {
                Some(front) => (front.len(), recv.front),
                None => break,
            };
            let available = front_len - front_start;
            if available == 0 {
                recv.chunks.pop_front();
                recv.front = 0;
                continue;
            }
            let take = available.min(buf.remaining());
            {
                let front = recv.chunks.front().expect("checked above");
                buf.put_slice(&front[front_start..front_start + take]);
            }
            recv.front += take;
            recv.buffered -= take;
            recv.delivered_since_grant += take;
            copied += take;
            if recv.front == front_len {
                recv.chunks.pop_front();
                recv.front = 0;
            }
        }

        if copied > 0 {
            self.session
                .inner
                .stats
                .bytes_down
                .fetch_add(copied as u64, Ordering::Relaxed);
            // Return credit once about half a window has been consumed. `try_send` keeps this
            // allocation-free and non-blocking; if the queue is full the credit is simply offered
            // again on the next read.
            let window = shared.window as usize;
            if recv.delivered_since_grant * 2 >= window {
                let credit = recv.delivered_since_grant;
                let queued = self
                    .session
                    .inner
                    .outbound
                    .try_send(Outbound::Message(Message::StreamWindow {
                        stream_id: shared.id,
                        credit: credit as u32,
                    }))
                    .is_ok();
                if queued {
                    recv.delivered_since_grant = 0;
                }
            }
            return Poll::Ready(Ok(()));
        }

        if recv.fin {
            return Poll::Ready(Ok(()));
        }

        if let Ok(mut slot) = shared.recv_waker.lock() {
            *slot = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}

impl AsyncWrite for VlpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let shared = &self.shared;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if shared.local_finished.load(Ordering::Relaxed) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream was shut down for writing",
            )));
        }
        if self.session.inner.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session is closed",
            )));
        }
        let mut credit = match shared.send_credit.lock() {
            Ok(credit) => credit,
            Err(_) => return Poll::Ready(Err(io::Error::other("stream state is poisoned"))),
        };
        if *credit == 0 {
            if let Ok(mut slot) = shared.send_waker.lock() {
                *slot = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        let take = buf.len().min(*credit as usize).min(MAX_STREAM_DATA);
        let message = Message::StreamData {
            stream_id: shared.id,
            data: buf[..take].to_vec(),
        };
        match self
            .session
            .inner
            .outbound
            .try_send(Outbound::Message(message))
        {
            Ok(()) => {
                *credit -= take as u64;
                self.session
                    .inner
                    .stats
                    .bytes_up
                    .fetch_add(take as u64, Ordering::Relaxed);
                Poll::Ready(Ok(take))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                if let Ok(mut wakers) = self.session.inner.capacity.lock() {
                    wakers.push(cx.waker().clone());
                }
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "session is closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Messages are handed to the writer task immediately on write, so there is nothing to
        // flush beyond that hand-off.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.shared.local_finished.swap(true, Ordering::SeqCst) {
            return Poll::Ready(Ok(()));
        }
        let _ = self.session.inner.enqueue(Message::StreamFin {
            stream_id: self.shared.id,
        });
        Poll::Ready(Ok(()))
    }
}

impl Drop for VlpStream {
    fn drop(&mut self) {
        // A dropped stream that was never half-closed must tell the peer to free its resources.
        if !self.shared.local_finished.swap(true, Ordering::SeqCst)
            && !self.shared.remote_finished.load(Ordering::Relaxed)
        {
            let _ = self.session.inner.enqueue(Message::StreamFin {
                stream_id: self.shared.id,
            });
        }
        self.session.inner.remove_stream(self.shared.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::BucketedPadding;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_psk() -> Psk {
        Psk::from_bytes(
            &(0u8..32)
                .map(|i| i.wrapping_mul(13).wrapping_add(11))
                .collect::<Vec<u8>>(),
        )
        .unwrap()
    }

    /// Waits until `session` holds at least `minimum` unused peer keys.
    async fn wait_for_peer_keys(session: &Session, minimum: usize, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while session.peer_keys() < minimum {
            assert!(
                Instant::now() < deadline,
                "the peer never published {minimum} usable one-time keys"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Builds a connected pair of sessions over an in-memory byte pipe.
    async fn session_pair(
        config: SessionConfig,
    ) -> (Session, Session, mpsc::Receiver<IncomingStream>) {
        let (a, b) = tokio::io::duplex(1 << 20);
        let psk = test_psk();
        let exporter = [7u8; 32];
        let identity = [0x42; 32];
        let padding = Arc::new(BucketedPadding::new()) as Arc<dyn PaddingPolicy>;

        let client_future = start_session(
            a,
            Role::Client,
            &psk,
            exporter,
            identity,
            config.clone(),
            padding.clone(),
        );
        let server_future =
            start_session(b, Role::Server, &psk, exporter, identity, config, padding);
        let (client, server) = tokio::join!(client_future, server_future);
        let client = client.expect("client session");
        let server = server.expect("server session");
        let incoming = server.incoming_streams().expect("incoming stream receiver");
        (client, server, incoming)
    }

    /// Opens a stream, answers it on the server side, and returns both ends.
    async fn connected_streams(
        client: &Session,
        server: &Session,
        incoming: &mut mpsc::Receiver<IncomingStream>,
    ) -> (VlpStream, VlpStream) {
        let open = tokio::spawn({
            let client = client.clone();
            async move { client.open_stream("example.test", 443).await }
        });
        let accepted = tokio::time::timeout(Duration::from_secs(5), incoming.recv())
            .await
            .expect("server must receive OPEN_STREAM")
            .expect("incoming channel open");
        assert_eq!(accepted.host, "example.test");
        assert_eq!(accepted.port, 443);
        let server_stream = accepted.stream;
        server
            .respond_open(server_stream.id(), OpenStatus::Ok, "")
            .expect("respond");
        let client_stream = open.await.unwrap().expect("the client stream should open");
        (client_stream, server_stream)
    }

    #[tokio::test]
    async fn handshake_establishes_a_session_on_both_sides() {
        let (client, server, _incoming) = session_pair(SessionConfig::default()).await;
        assert_eq!(client.session_id(), server.session_id());
        assert!(!client.is_closed());
        assert!(!server.is_closed());
        // Key offers travel as ordinary frames, so they arrive shortly after the handshake.
        wait_for_peer_keys(&client, 1, Duration::from_secs(5)).await;
        wait_for_peer_keys(&server, 1, Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn a_wrong_pre_shared_key_fails_the_handshake() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let padding = Arc::new(BucketedPadding::new()) as Arc<dyn PaddingPolicy>;
        let good = test_psk();
        let bad = Psk::from_bytes(
            &(0u8..32)
                .map(|i| i.wrapping_mul(29).wrapping_add(3))
                .collect::<Vec<u8>>(),
        )
        .unwrap();

        let client = start_session(
            a,
            Role::Client,
            &good,
            [1u8; 32],
            [0x42; 32],
            SessionConfig::default(),
            padding.clone(),
        );
        let server = start_session(
            b,
            Role::Server,
            &bad,
            [1u8; 32],
            [0x42; 32],
            SessionConfig::default(),
            padding,
        );
        let (client, server) = tokio::join!(client, server);
        assert!(client.is_err(), "the client must reject the wrong key");
        assert!(server.is_err(), "the server must reject the wrong key");
    }

    #[tokio::test]
    async fn a_changed_tls_exporter_fails_the_handshake() {
        // This is the relay case: the two legs are different TLS sessions with different
        // exporters, so the confirmation MAC cannot verify.
        let (a, b) = tokio::io::duplex(64 * 1024);
        let padding = Arc::new(BucketedPadding::new()) as Arc<dyn PaddingPolicy>;
        let psk = test_psk();
        let client = start_session(
            a,
            Role::Client,
            &psk,
            [1u8; 32],
            [0x42; 32],
            SessionConfig::default(),
            padding.clone(),
        );
        let server = start_session(
            b,
            Role::Server,
            &psk,
            [2u8; 32],
            [0x42; 32],
            SessionConfig::default(),
            padding,
        );
        let (client, server) = tokio::join!(client, server);
        assert!(client.is_err());
        assert!(server.is_err());
    }

    #[tokio::test]
    async fn streams_carry_data_in_both_directions() {
        let (client, server, mut incoming) = session_pair(SessionConfig::default()).await;
        let (mut client_stream, mut server_stream) =
            connected_streams(&client, &server, &mut incoming).await;

        client_stream.write_all(b"request body").await.unwrap();
        client_stream.flush().await.unwrap();
        let mut got = vec![0u8; 12];
        tokio::time::timeout(Duration::from_secs(5), server_stream.read_exact(&mut got))
            .await
            .expect("server read timed out")
            .unwrap();
        assert_eq!(got, b"request body");

        server_stream.write_all(b"response body").await.unwrap();
        let mut back = vec![0u8; 13];
        tokio::time::timeout(Duration::from_secs(5), client_stream.read_exact(&mut back))
            .await
            .expect("client read timed out")
            .unwrap();
        assert_eq!(back, b"response body");
    }

    #[tokio::test]
    async fn a_large_transfer_arrives_intact() {
        let (client, server, mut incoming) = session_pair(SessionConfig::default()).await;
        let (mut client_stream, mut server_stream) =
            connected_streams(&client, &server, &mut incoming).await;

        const SIZE: usize = 3 * 1024 * 1024;
        let payload: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            client_stream.write_all(&payload).await.unwrap();
            client_stream.shutdown().await.unwrap();
            client_stream
        });
        let mut received = Vec::with_capacity(SIZE);
        tokio::time::timeout(
            Duration::from_secs(30),
            server_stream.read_to_end(&mut received),
        )
        .await
        .expect("large transfer timed out")
        .unwrap();
        let _client_stream = writer.await.unwrap();
        assert_eq!(received.len(), SIZE);
        assert_eq!(received, expected, "the payload was altered in transit");
    }

    #[tokio::test]
    async fn multiple_streams_are_multiplexed_without_mixing() {
        let (client, server, mut incoming) = session_pair(SessionConfig::default()).await;
        const STREAMS: usize = 8;

        let mut server_streams = Vec::new();
        let mut client_streams = Vec::new();
        for index in 0..STREAMS {
            let open = tokio::spawn({
                let client = client.clone();
                async move {
                    client
                        .open_stream(&format!("host{index}.test"), 80 + index as u16)
                        .await
                }
            });
            let accepted = incoming.recv().await.expect("incoming");
            assert_eq!(accepted.host, format!("host{index}.test"));
            server
                .respond_open(accepted.stream.id(), OpenStatus::Ok, "")
                .unwrap();
            server_streams.push(accepted.stream);
            client_streams.push(open.await.unwrap().unwrap());
        }

        // Every stream carries a distinct payload in both directions at once.
        let mut tasks = Vec::new();
        for (index, mut client_stream) in client_streams.into_iter().enumerate() {
            let mut server_stream = server_streams.remove(0);
            tasks.push(tokio::spawn(async move {
                let payload = format!("payload-{index}").repeat(64 + index);
                let expected = payload.clone();
                client_stream.write_all(payload.as_bytes()).await.unwrap();
                client_stream.shutdown().await.unwrap();
                let mut got = Vec::new();
                server_stream.read_to_end(&mut got).await.unwrap();
                assert_eq!(got, expected.as_bytes(), "stream {index} was corrupted");

                let reply = format!("reply-{index}").repeat(32);
                let expected_reply = reply.clone();
                server_stream.write_all(reply.as_bytes()).await.unwrap();
                server_stream.shutdown().await.unwrap();
                let mut back = Vec::new();
                client_stream.read_to_end(&mut back).await.unwrap();
                assert_eq!(back, expected_reply.as_bytes());
            }));
        }
        for task in tasks {
            tokio::time::timeout(Duration::from_secs(20), task)
                .await
                .expect("multiplexed transfer timed out")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn flow_control_parks_a_writer_until_the_reader_catches_up() {
        let config = SessionConfig {
            initial_window: MIN_WINDOW,
            ..SessionConfig::default()
        };
        let (client, server, mut incoming) = session_pair(config).await;
        let (mut client_stream, mut server_stream) =
            connected_streams(&client, &server, &mut incoming).await;

        assert_eq!(client_stream.send_credit(), MIN_WINDOW as u64);

        // Write far more than the window without reading on the server: the writer must park.
        let payload = vec![0x5au8; MIN_WINDOW as usize * 4];
        let writer = tokio::spawn(async move {
            client_stream.write_all(&payload).await.unwrap();
            client_stream
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !writer.is_finished(),
            "the writer completed despite the peer not reading: flow control is not applied"
        );

        // Drain on the server; the writer must now finish.
        let mut received = Vec::new();
        let drain = tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                match server_stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => received.extend_from_slice(&buf[..n]),
                }
            }
            received
        });
        let stream = tokio::time::timeout(Duration::from_secs(15), writer)
            .await
            .expect("the writer never resumed after credit was returned")
            .unwrap();
        drop(stream);
        let received = tokio::time::timeout(Duration::from_secs(15), drain)
            .await
            .expect("drain timed out")
            .unwrap();
        assert_eq!(received.len(), MIN_WINDOW as usize * 4);
    }

    #[tokio::test]
    async fn half_close_is_propagated() {
        let (client, server, mut incoming) = session_pair(SessionConfig::default()).await;
        let (mut client_stream, mut server_stream) =
            connected_streams(&client, &server, &mut incoming).await;

        client_stream.write_all(b"half").await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), server_stream.read_to_end(&mut got))
            .await
            .expect("half-close did not reach the server")
            .unwrap();
        assert_eq!(got, b"half");

        // The server can still answer after seeing the client's FIN.
        server_stream.write_all(b"still here").await.unwrap();
        let mut back = vec![0u8; b"still here".len()];
        tokio::time::timeout(Duration::from_secs(5), client_stream.read_exact(&mut back))
            .await
            .expect("the reply after half-close never arrived")
            .unwrap();
        assert_eq!(back, b"still here");
    }

    #[tokio::test]
    async fn a_reset_surfaces_as_a_connection_reset() {
        let (client, server, mut incoming) = session_pair(SessionConfig::default()).await;
        let (mut client_stream, server_stream) =
            connected_streams(&client, &server, &mut incoming).await;

        server_stream.reset(7, "target unreachable");
        let mut buf = [0u8; 16];
        let error = tokio::time::timeout(Duration::from_secs(5), client_stream.read(&mut buf))
            .await
            .expect("timed out waiting for the reset")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn a_refused_stream_reports_the_status() {
        let (client, server, mut incoming) = session_pair(SessionConfig::default()).await;
        let open = tokio::spawn({
            let client = client.clone();
            async move { client.open_stream("blocked.test", 22).await }
        });
        let accepted = incoming.recv().await.unwrap();
        server
            .respond_open(
                accepted.stream.id(),
                OpenStatus::PolicyDenied,
                "private network",
            )
            .unwrap();
        let error = open.await.unwrap().unwrap_err();
        assert!(matches!(error, SessionError::OpenRefused { .. }), "{error}");
        assert_eq!(
            client.open_streams(),
            0,
            "the refused stream was not cleaned up"
        );
    }

    #[tokio::test]
    async fn ping_reports_a_round_trip() {
        let (client, _server, _incoming) = session_pair(SessionConfig::default()).await;
        let rtt = tokio::time::timeout(Duration::from_secs(5), client.ping())
            .await
            .expect("ping timed out")
            .unwrap();
        assert!(rtt < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn one_time_keys_are_replenished_during_a_long_transfer() {
        // A small pool forces the replenishment path to run repeatedly.
        let config = SessionConfig {
            key_pool_size: 16,
            ..SessionConfig::default()
        };
        let (client, server, mut incoming) = session_pair(config).await;
        let (mut client_stream, mut server_stream) =
            connected_streams(&client, &server, &mut incoming).await;

        let payload = vec![0x11u8; 512 * 1024];
        let expected = payload.clone();
        let writer = tokio::spawn(async move {
            client_stream.write_all(&payload).await.unwrap();
            client_stream.shutdown().await.unwrap();
        });
        let mut received = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(30),
            server_stream.read_to_end(&mut received),
        )
        .await
        .expect("transfer with a small key pool timed out")
        .unwrap();
        writer.await.unwrap();
        assert_eq!(received.len(), expected.len());
        assert_eq!(received, expected);
        assert!(
            server.stats().keys_consumed >= 16,
            "the transfer did not consume and replenish keys"
        );
        assert!(server.local_keys() > 0, "the pool was not replenished");
    }

    #[tokio::test]
    async fn cover_traffic_is_accepted_and_discarded() {
        let (client, _server, _incoming) = session_pair(SessionConfig::default()).await;
        for len in [16usize, 512, 4096] {
            client.send_cover(len).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        let stats = client.stats();
        assert_eq!(stats.cover_sent, 3);
        assert!(stats.cover_bytes >= 4624);
        assert!(!client.is_closed(), "cover traffic closed the session");
    }

    #[tokio::test]
    async fn closing_the_session_fails_every_stream() {
        let (client, server, mut incoming) = session_pair(SessionConfig::default()).await;
        let (mut client_stream, _server_stream) =
            connected_streams(&client, &server, &mut incoming).await;

        server.close("shutting down").await;
        let mut buf = [0u8; 16];
        let outcome = tokio::time::timeout(Duration::from_secs(5), client_stream.read(&mut buf))
            .await
            .expect("the client was never told the session ended");
        assert!(outcome.is_err() || outcome.unwrap() == 0);
        assert!(client.is_closed());
        assert_eq!(client.open_streams(), 0);
    }

    #[tokio::test]
    async fn the_stream_limit_is_enforced() {
        let config = SessionConfig {
            max_streams: 3,
            ..SessionConfig::default()
        };
        let (client, server, mut incoming) = session_pair(config).await;

        let mut accepted = Vec::new();
        for _ in 0..3 {
            let open = tokio::spawn({
                let client = client.clone();
                async move { client.open_stream("a.test", 80).await }
            });
            let incoming_stream = incoming.recv().await.unwrap();
            server
                .respond_open(incoming_stream.stream.id(), OpenStatus::Ok, "")
                .unwrap();
            accepted.push((incoming_stream.stream, open.await.unwrap().unwrap()));
        }

        // The client enforces the same limit locally and refuses the fourth stream without ever
        // putting an OPEN_STREAM on the wire.
        let error = client.open_stream("a.test", 80).await.unwrap_err();
        assert!(matches!(error, SessionError::TooManyStreams(3)), "{error}");

        // Freeing a slot lets a new stream through.
        drop(accepted.pop());
        tokio::time::sleep(Duration::from_millis(50)).await;
        let open = tokio::spawn({
            let client = client.clone();
            async move { client.open_stream("b.test", 80).await }
        });
        let accepted_again = incoming.recv().await.unwrap();
        server
            .respond_open(accepted_again.stream.id(), OpenStatus::Ok, "")
            .unwrap();
        let stream = open.await.unwrap().expect("a freed slot must be reusable");
        drop(stream);
        drop(accepted);
    }

    #[tokio::test]
    async fn dropping_a_stream_closes_it_and_frees_the_slot() {
        let (client, server, mut incoming) = session_pair(SessionConfig::default()).await;
        let (client_stream, mut server_stream) =
            connected_streams(&client, &server, &mut incoming).await;
        assert_eq!(client.open_streams(), 1);
        drop(client_stream);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(client.open_streams(), 0);

        // The server sees an end of stream rather than hanging.
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), server_stream.read_to_end(&mut rest))
            .await
            .expect("the server never saw the stream end")
            .unwrap();
    }

    #[tokio::test]
    async fn concurrent_opens_do_not_interfere() {
        let (client, server, mut incoming) = session_pair(SessionConfig::default()).await;
        const STREAMS: usize = 16;

        let mut opens = Vec::new();
        for index in 0..STREAMS {
            let client = client.clone();
            opens.push(tokio::spawn(async move {
                client
                    .open_stream(&format!("concurrent{index}.test"), 443)
                    .await
                    .map(|stream| (index, stream))
            }));
        }

        let mut server_streams = Vec::new();
        for _ in 0..STREAMS {
            let accepted = incoming.recv().await.unwrap();
            server
                .respond_open(accepted.stream.id(), OpenStatus::Ok, "")
                .unwrap();
            server_streams.push(accepted.stream);
        }

        let mut names = std::collections::HashSet::new();
        let mut streams = Vec::new();
        for open in opens {
            let (index, stream) = open.await.unwrap().unwrap();
            assert!(
                names.insert(stream.id()),
                "stream {index} reused an identifier"
            );
            streams.push(stream);
        }
        assert_eq!(names.len(), STREAMS);
        assert_eq!(client.open_streams(), STREAMS);
        drop(streams);
    }

    #[tokio::test]
    async fn statistics_track_traffic() {
        let (client, server, mut incoming) = session_pair(SessionConfig::default()).await;
        let (mut client_stream, mut server_stream) =
            connected_streams(&client, &server, &mut incoming).await;
        client_stream.write_all(b"hello there").await.unwrap();
        client_stream.shutdown().await.unwrap();
        let mut got = Vec::new();
        server_stream.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello there");

        let stats = client.stats();
        assert!(stats.frames_sent > 0);
        assert!(stats.frames_received > 0);
        assert!(stats.bytes_up >= 11);
        assert_eq!(stats.streams_opened, 1);
        assert_eq!(stats.frames_rejected, 0);
    }

    #[tokio::test]
    async fn a_client_refuses_a_stream_opened_by_the_server() {
        let (client, server, _incoming) = session_pair(SessionConfig::default()).await;
        // Reach into the server's codec to send an OPEN_STREAM as if the roles were reversed.
        server
            .inner
            .enqueue(Message::OpenStream {
                stream_id: 99,
                host: "evil.test".to_string(),
                port: 80,
                kind: crate::message::StreamKind::Tcp,
                initial_window: DEFAULT_WINDOW,
            })
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            client.is_closed(),
            "the client accepted a server-initiated stream"
        );
    }
}

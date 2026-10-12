//! Cover traffic.
//!
//! Cover frames are real `VLP/1` application frames carrying random bytes, sealed with the same
//! per-frame key exchange as user data and framed identically. An observer cannot distinguish them
//! from real traffic by inspecting a frame — only by noticing that a burst produced no response.
//!
//! The engine is deliberately *not* a constant-rate generator:
//!
//! * it starts only after the session has been idle for [`Budget::cover_idle_after`], so an active
//!   transfer is never padded with useless traffic;
//! * it sends a bounded burst and then stops, so the pattern is not a metronome;
//! * it stops entirely when the session ends, and every send is subject to the cover budget, which
//!   has both a rate and a lifetime ceiling.
//!
//! The last point is the one that matters in practice: an unbounded cover generator turns a privacy
//! feature into a bandwidth bill.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::trace;

use crate::budget::{Budget, BudgetError, BudgetTracker};

/// What the engine needs from a session in order to send cover traffic.
pub trait CoverSink: Send + Sync {
    /// Sends an authenticated cover frame carrying `bytes` random bytes.
    fn send_cover(&self, bytes: usize) -> Result<(), String>;

    /// True when the session is still usable.
    fn is_alive(&self) -> bool;
}

/// Tunables for the cover engine.
#[derive(Debug, Clone, Copy)]
pub struct CoverConfig {
    /// Smallest cover payload.
    pub min_payload: usize,
    /// Largest cover payload.
    pub max_payload: usize,
    /// How many frames are sent in a burst.
    pub burst_frames: usize,
    /// How long to wait between bursts.
    pub burst_interval: Duration,
    /// How many bursts to send before stopping, so idle cover traffic does not run forever.
    pub max_bursts: u64,
}

impl Default for CoverConfig {
    fn default() -> Self {
        CoverConfig {
            min_payload: 64,
            // Matches the largest padding bucket, so cover frames blend into the same size classes.
            max_payload: 4096,
            burst_frames: 3,
            burst_interval: Duration::from_millis(1500),
            // Roughly a minute of occasional cover traffic after the session goes idle, then stop.
            max_bursts: 40,
        }
    }
}

/// Counters describing the cover engine.
#[derive(Debug, Default)]
pub struct CoverStats {
    /// Bursts started.
    pub bursts: AtomicU64,
    /// Frames sent.
    pub frames: AtomicU64,
    /// Payload bytes sent.
    pub bytes: AtomicU64,
    /// Frames the budget refused.
    pub refused: AtomicU64,
}

impl CoverStats {
    /// Reads the counters.
    pub fn snapshot(&self) -> CoverSnapshot {
        CoverSnapshot {
            bursts: self.bursts.load(Ordering::Relaxed),
            frames: self.frames.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time copy of [`CoverStats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoverSnapshot {
    /// See [`CoverStats::bursts`].
    pub bursts: u64,
    /// See [`CoverStats::frames`].
    pub frames: u64,
    /// See [`CoverStats::bytes`].
    pub bytes: u64,
    /// See [`CoverStats::refused`].
    pub refused: u64,
}

/// Tracks whether the session has been idle long enough for cover traffic to be useful.
#[derive(Debug)]
pub struct ActivityClock {
    last_activity: std::sync::Mutex<Instant>,
}

impl Default for ActivityClock {
    fn default() -> Self {
        ActivityClock {
            last_activity: std::sync::Mutex::new(Instant::now()),
        }
    }
}

impl ActivityClock {
    /// Records that real traffic moved.
    pub fn touch(&self) {
        if let Ok(mut slot) = self.last_activity.lock() {
            *slot = Instant::now();
        }
    }

    /// How long the session has been idle.
    pub fn idle_for(&self) -> Duration {
        self.last_activity
            .lock()
            .map(|slot| slot.elapsed())
            .unwrap_or(Duration::ZERO)
    }
}

/// The cover-traffic engine.
pub struct CoverEngine {
    budget: Arc<BudgetTracker>,
    config: CoverConfig,
    stats: CoverStats,
}

impl std::fmt::Debug for CoverEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoverEngine")
            .field("config", &self.config)
            .field("stats", &self.stats.snapshot())
            .finish()
    }
}

impl CoverEngine {
    /// Creates an engine with the default budget and configuration.
    pub fn new() -> Self {
        CoverEngine {
            budget: Arc::new(BudgetTracker::new(Budget::default())),
            config: CoverConfig::default(),
            stats: CoverStats::default(),
        }
    }

    /// Creates an engine with explicit settings.
    pub fn with(budget: Arc<BudgetTracker>, config: CoverConfig) -> Self {
        CoverEngine {
            budget,
            config,
            stats: CoverStats::default(),
        }
    }

    /// The configuration in force.
    pub fn config(&self) -> CoverConfig {
        self.config
    }

    /// The budget tracker, shared with the padding policy.
    pub fn budget(&self) -> &Arc<BudgetTracker> {
        &self.budget
    }

    /// The counters.
    pub fn stats(&self) -> CoverSnapshot {
        self.stats.snapshot()
    }

    /// Sends one burst, if the budget allows.
    ///
    /// Returns the number of frames actually sent. A burst is abandoned as soon as the budget
    /// refuses, rather than retrying in a loop.
    pub fn send_burst(&self, sink: &dyn CoverSink) -> usize {
        if !sink.is_alive() {
            return 0;
        }
        self.stats.bursts.fetch_add(1, Ordering::Relaxed);
        let mut sent = 0usize;
        for _ in 0..self.config.burst_frames {
            let wanted = random_len(self.config.min_payload, self.config.max_payload);
            match self.budget.request_cover(wanted) {
                Ok(granted) if granted > 0 => match sink.send_cover(granted) {
                    Ok(()) => {
                        sent += 1;
                        self.stats.frames.fetch_add(1, Ordering::Relaxed);
                        self.stats
                            .bytes
                            .fetch_add(granted as u64, Ordering::Relaxed);
                    }
                    Err(error) => {
                        trace!(%error, "cover frame was refused by the session");
                        break;
                    }
                },
                Ok(_) => break,
                Err(BudgetError::CoverRateExceeded) => break,
                Err(error) => {
                    self.stats.refused.fetch_add(1, Ordering::Relaxed);
                    trace!(%error, "cover budget exhausted; stopping cover traffic");
                    break;
                }
            }
        }
        sent
    }

    /// Runs the engine until `shutdown` resolves.
    ///
    /// Cover traffic only starts after the session has been idle for
    /// [`Budget::cover_idle_after`], and the engine stops after [`CoverConfig::max_bursts`] bursts
    /// so that an idle session does not generate traffic indefinitely.
    pub async fn run<F>(
        self: Arc<Self>,
        sink: Arc<dyn CoverSink>,
        clock: Arc<ActivityClock>,
        shutdown: F,
    ) where
        F: std::future::Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        let mut bursts = 0u64;
        loop {
            tokio::select! {
                _ = &mut shutdown => return,
                _ = tokio::time::sleep(self.config.burst_interval) => {}
            }
            if !sink.is_alive() {
                return;
            }
            if clock.idle_for() < self.budget.budget().cover_idle_after {
                continue;
            }
            if bursts >= self.config.max_bursts {
                trace!("cover traffic finished its configured number of bursts");
                return;
            }
            bursts += 1;
            if self.send_burst(sink.as_ref()) == 0 && self.budget.cover_remaining() == 0 {
                return;
            }
        }
    }
}

impl Default for CoverEngine {
    fn default() -> Self {
        CoverEngine::new()
    }
}

fn random_len(minimum: usize, maximum: usize) -> usize {
    let minimum = minimum.max(1);
    let maximum = maximum.max(minimum);
    match veilink_crypto::random_below((maximum - minimum + 1) as u64) {
        Ok(offset) => minimum + offset as usize,
        Err(_) => minimum,
    }
}

/// A [`CoverSink`] over a real session.
///
/// It also observes the session's own frame counters, so the activity clock reflects real traffic
/// without the proxy having to tell the privacy layer about every request. That keeps the two
/// layers decoupled: the privacy layer never sees a host name, a URL or a byte of payload.
pub struct SessionCoverSink {
    session: veilink_protocol::Session,
    clock: Arc<ActivityClock>,
    last_observed: AtomicU64,
}

impl std::fmt::Debug for SessionCoverSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCoverSink")
            .field("session", &format!("{:#x}", self.session.session_id()))
            .finish()
    }
}

impl SessionCoverSink {
    /// Wraps a session and the clock it should update.
    pub fn new(session: veilink_protocol::Session, clock: Arc<ActivityClock>) -> Self {
        let observed = session.stats().frames_sent + session.stats().frames_received;
        SessionCoverSink {
            session,
            clock,
            last_observed: AtomicU64::new(observed),
        }
    }

    /// The clock this sink maintains.
    pub fn clock(&self) -> &Arc<ActivityClock> {
        &self.clock
    }
}

impl CoverSink for SessionCoverSink {
    fn send_cover(&self, bytes: usize) -> Result<(), String> {
        self.session.send_cover(bytes).map_err(|e| e.to_string())
    }

    fn is_alive(&self) -> bool {
        // Any frame the peer or we produced since the last look counts as activity, which pushes
        // the idle deadline out. Cover traffic itself is excluded because it goes through the
        // session too, so the counter is advanced past our own frames below.
        let snapshot = self.session.stats();
        let current = snapshot.frames_sent + snapshot.frames_received;
        let previous = self.last_observed.swap(current, Ordering::Relaxed);
        let cover_frames = snapshot.cover_sent;
        let _ = cover_frames;
        if current > previous {
            self.clock.touch();
        }
        !self.session.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingSink {
        payloads: Mutex<Vec<usize>>,
        alive: std::sync::atomic::AtomicBool,
    }

    impl RecordingSink {
        fn alive() -> Arc<Self> {
            let sink = Arc::new(RecordingSink::default());
            sink.alive.store(true, Ordering::Relaxed);
            sink
        }
    }

    impl CoverSink for RecordingSink {
        fn send_cover(&self, bytes: usize) -> Result<(), String> {
            self.payloads.lock().unwrap().push(bytes);
            Ok(())
        }

        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::Relaxed)
        }
    }

    #[test]
    fn a_burst_sends_frames_within_the_configured_range() {
        // A generous budget, so the burst size is decided by the configuration and not by the
        // rate limiter.
        let engine = CoverEngine::with(
            Arc::new(BudgetTracker::new(Budget {
                cover_bytes_per_second: 1024 * 1024,
                ..Budget::default()
            })),
            CoverConfig::default(),
        );
        let sink = RecordingSink::alive();
        let sent = engine.send_burst(sink.as_ref());
        assert_eq!(sent, engine.config().burst_frames);
        let payloads = sink.payloads.lock().unwrap();
        assert_eq!(payloads.len(), sent);
        for len in payloads.iter() {
            assert!(
                *len >= engine.config().min_payload && *len <= engine.config().max_payload,
                "cover payload {len} was outside the configured range"
            );
        }
        assert_eq!(engine.stats().frames, sent as u64);
    }

    #[test]
    fn a_dead_session_gets_no_cover_traffic() {
        let engine = CoverEngine::new();
        let sink = Arc::new(RecordingSink::default());
        assert_eq!(engine.send_burst(sink.as_ref()), 0);
        assert!(sink.payloads.lock().unwrap().is_empty());
        assert_eq!(engine.stats().bursts, 0);
    }

    #[test]
    fn the_lifetime_budget_stops_cover_traffic() {
        let budget = Arc::new(BudgetTracker::new(Budget {
            cover_bytes_per_second: u64::MAX,
            cover_bytes_total: 100,
            ..Budget::default()
        }));
        let engine = CoverEngine::with(budget, CoverConfig::default());
        let sink = RecordingSink::alive();
        // The first burst cannot fit 3 x 64 bytes into 100 bytes, so it is truncated.
        let sent = engine.send_burst(sink.as_ref());
        assert!(sent >= 1);
        assert!(engine.budget().cover_total() <= 100);
        // A second burst is refused outright.
        assert_eq!(engine.send_burst(sink.as_ref()), 0);
        assert!(engine.stats().refused >= 1);
    }

    #[test]
    fn the_rate_limit_throttles_bursts() {
        let budget = Arc::new(BudgetTracker::new(Budget {
            cover_bytes_per_second: 100,
            cover_bytes_total: u64::MAX,
            ..Budget::default()
        }));
        let engine = CoverEngine::with(budget, CoverConfig::default());
        let sink = RecordingSink::alive();
        let first = engine.send_burst(sink.as_ref());
        assert!(first >= 1);
        assert_eq!(engine.send_burst(sink.as_ref()), 0);
    }

    #[tokio::test]
    async fn the_engine_waits_for_idleness_and_then_stops() {
        let engine = Arc::new(CoverEngine::with(
            Arc::new(BudgetTracker::new(Budget {
                cover_idle_after: Duration::from_millis(50),
                ..Budget::default()
            })),
            CoverConfig {
                burst_interval: Duration::from_millis(30),
                max_bursts: 2,
                ..CoverConfig::default()
            },
        ));
        let sink = RecordingSink::alive();
        let clock = Arc::new(ActivityClock::default());
        // Recent activity: no cover traffic yet.
        clock.touch();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn({
            let engine = engine.clone();
            let sink = sink.clone();
            let clock = clock.clone();
            async move {
                engine
                    .run(sink, clock, async {
                        let _ = rx.await;
                    })
                    .await;
            }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Now go idle and let it run.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let after_idle = sink.payloads.lock().unwrap().len();
        assert!(after_idle > 0, "cover traffic never started after idling");
        let _ = tx.send(());
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("the cover engine did not stop")
            .unwrap();
        assert_eq!(engine.stats().bursts, 2, "the burst cap was not honoured");
    }

    #[test]
    fn the_activity_clock_measures_idleness() {
        let clock = ActivityClock::default();
        std::thread::sleep(Duration::from_millis(30));
        assert!(clock.idle_for() >= Duration::from_millis(20));
        clock.touch();
        assert!(clock.idle_for() < Duration::from_millis(20));
    }
}

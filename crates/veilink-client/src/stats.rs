//! Runtime statistics shared by the client and server runtimes.
//!
//! The counters are plain atomics with relaxed ordering: they are diagnostic telemetry, not
//! synchronisation primitives. Nothing sensitive (no domain names, no URLs) is recorded here.

use std::sync::atomic::{AtomicU64, Ordering};

/// Counters describing the state of a running Veilink process.
#[derive(Debug, Default)]
pub struct Stats {
    /// Accepted client (or peer) connections.
    pub connections_total: AtomicU64,
    /// Connections currently being served.
    pub connections_active: AtomicU64,
    /// Tunnelled streams opened in total.
    pub streams_total: AtomicU64,
    /// Streams currently open.
    pub streams_active: AtomicU64,
    /// Requests routed through the remote server.
    pub requests_proxied: AtomicU64,
    /// Requests connected directly from the local host.
    pub requests_direct: AtomicU64,
    /// Requests rejected before any connection was attempted.
    pub requests_rejected: AtomicU64,
    /// Bytes uploaded by the local application.
    pub bytes_up: AtomicU64,
    /// Bytes downloaded to the local application.
    pub bytes_down: AtomicU64,
    /// Encrypted frames sent over the tunnel.
    pub frames_sent: AtomicU64,
    /// Encrypted frames received over the tunnel.
    pub frames_received: AtomicU64,
    /// Cover-traffic frames sent.
    pub cover_frames_sent: AtomicU64,
    /// Cover-traffic payload bytes sent.
    pub cover_bytes_sent: AtomicU64,
    /// Session (re)connection attempts.
    pub session_connects: AtomicU64,
    /// Successful session establishments.
    pub session_established: AtomicU64,
    /// Failed authentication handshakes observed.
    pub auth_failures: AtomicU64,
    /// DNS lookups performed by the remote resolver.
    pub dns_queries: AtomicU64,
    /// DNS cache hits.
    pub dns_cache_hits: AtomicU64,
    /// DNS resolution failures.
    pub dns_failures: AtomicU64,
    /// Outbound connections refused by the egress policy.
    pub egress_denied: AtomicU64,
    /// Rejected frames (authentication, replay, malformed).
    pub frames_rejected: AtomicU64,
}

impl Stats {
    /// Creates a zeroed counter set.
    pub fn new() -> Self {
        Stats::default()
    }

    /// Increments `counter` by one.
    pub fn inc(&self, counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Adds `delta` to `counter`.
    pub fn add(&self, counter: &AtomicU64, delta: u64) {
        counter.fetch_add(delta, Ordering::Relaxed);
    }

    /// Decrements `counter`, saturating at zero.
    pub fn dec(&self, counter: &AtomicU64) {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_sub(1))
        });
    }

    /// Reads `counter`.
    pub fn get(&self, counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// A consistent-enough snapshot for logging.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            connections_total: self.get(&self.connections_total),
            connections_active: self.get(&self.connections_active),
            streams_total: self.get(&self.streams_total),
            streams_active: self.get(&self.streams_active),
            requests_proxied: self.get(&self.requests_proxied),
            requests_direct: self.get(&self.requests_direct),
            requests_rejected: self.get(&self.requests_rejected),
            bytes_up: self.get(&self.bytes_up),
            bytes_down: self.get(&self.bytes_down),
            frames_sent: self.get(&self.frames_sent),
            frames_received: self.get(&self.frames_received),
            cover_frames_sent: self.get(&self.cover_frames_sent),
            cover_bytes_sent: self.get(&self.cover_bytes_sent),
            session_connects: self.get(&self.session_connects),
            session_established: self.get(&self.session_established),
            auth_failures: self.get(&self.auth_failures),
            dns_queries: self.get(&self.dns_queries),
            dns_cache_hits: self.get(&self.dns_cache_hits),
            dns_failures: self.get(&self.dns_failures),
            egress_denied: self.get(&self.egress_denied),
            frames_rejected: self.get(&self.frames_rejected),
        }
    }
}

/// A point-in-time copy of [`Stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// See [`Stats::connections_total`].
    pub connections_total: u64,
    /// See [`Stats::connections_active`].
    pub connections_active: u64,
    /// See [`Stats::streams_total`].
    pub streams_total: u64,
    /// See [`Stats::streams_active`].
    pub streams_active: u64,
    /// See [`Stats::requests_proxied`].
    pub requests_proxied: u64,
    /// See [`Stats::requests_direct`].
    pub requests_direct: u64,
    /// See [`Stats::requests_rejected`].
    pub requests_rejected: u64,
    /// See [`Stats::bytes_up`].
    pub bytes_up: u64,
    /// See [`Stats::bytes_down`].
    pub bytes_down: u64,
    /// See [`Stats::frames_sent`].
    pub frames_sent: u64,
    /// See [`Stats::frames_received`].
    pub frames_received: u64,
    /// See [`Stats::cover_frames_sent`].
    pub cover_frames_sent: u64,
    /// See [`Stats::cover_bytes_sent`].
    pub cover_bytes_sent: u64,
    /// See [`Stats::session_connects`].
    pub session_connects: u64,
    /// See [`Stats::session_established`].
    pub session_established: u64,
    /// See [`Stats::auth_failures`].
    pub auth_failures: u64,
    /// See [`Stats::dns_queries`].
    pub dns_queries: u64,
    /// See [`Stats::dns_cache_hits`].
    pub dns_cache_hits: u64,
    /// See [`Stats::dns_failures`].
    pub dns_failures: u64,
    /// See [`Stats::egress_denied`].
    pub egress_denied: u64,
    /// See [`Stats::frames_rejected`].
    pub frames_rejected: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_track_values() {
        let stats = Stats::new();
        stats.inc(&stats.connections_total);
        stats.add(&stats.bytes_up, 4096);
        stats.inc(&stats.connections_active);
        stats.dec(&stats.connections_active);
        stats.dec(&stats.connections_active); // saturates at zero
        let snap = stats.snapshot();
        assert_eq!(snap.connections_total, 1);
        assert_eq!(snap.bytes_up, 4096);
        assert_eq!(snap.connections_active, 0);
    }
}

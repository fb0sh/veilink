//! Outbound send scheduling.
//!
//! The session writer drains its queue and transmits in one pass, which is what makes the frame
//! sequence order match the wire order. A scheduler sits between "seal a frame" and "write it" and
//! decides three things:
//!
//! * how many queued frames may be coalesced into one write;
//! * how long to wait before the next batch.
//!
//! Two properties are non-negotiable, and the type system cannot express them, so they are stated
//! here and enforced by the implementations in `veilink-privacy`:
//!
//! 1. **No unbounded delay.** A scheduler returns a finite delay, and the writer additionally caps
//!    the wait at its own maximum. A policy that could delay a frame forever would turn a privacy
//!    feature into a denial of service.
//! 2. **No starvation.** When a message has been waiting longer than the maximum, the delay is
//!    zero regardless of what the policy would prefer.
//!
//! The default implementation sends immediately, which is what a caller gets if no privacy policy
//! is installed.

use std::time::Duration;

/// What the writer knows when it asks for a delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchContext {
    /// Number of frames already coalesced into this write.
    pub batch_len: usize,
    /// Total plaintext bytes in this batch.
    pub batch_bytes: usize,
    /// How long the oldest message in the batch has been queued.
    pub oldest_wait: Duration,
    /// How many messages remain in the queue behind this batch.
    pub queued_behind: usize,
}

/// Decides how the writer groups and paces outbound frames.
pub trait SendScheduler: Send + Sync + std::fmt::Debug {
    /// The largest number of messages that may be coalesced into one write.
    fn max_batch(&self) -> usize;

    /// The largest number of plaintext bytes that may be coalesced into one write.
    fn max_batch_bytes(&self) -> usize;

    /// The delay to apply before writing a batch described by `context`.
    ///
    /// Returning [`Duration::ZERO`] means "write now".
    fn delay(&self, context: &BatchContext) -> Duration;

    /// A short name used in logs.
    fn name(&self) -> &'static str;
}

/// The default scheduler: coalesce what is already queued, then write immediately.
#[derive(Debug, Clone, Copy, Default)]
pub struct ImmediateScheduler;

impl SendScheduler for ImmediateScheduler {
    fn max_batch(&self) -> usize {
        // Coalescing whatever has already been queued costs nothing and reduces syscalls, but the
        // batch is bounded so that one very busy stream cannot delay another by an unbounded amount.
        16
    }

    fn max_batch_bytes(&self) -> usize {
        crate::frame::MAX_PAYLOAD * 4
    }

    fn delay(&self, _context: &BatchContext) -> Duration {
        Duration::ZERO
    }

    fn name(&self) -> &'static str {
        "immediate"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_immediate_scheduler_never_delays() {
        let scheduler = ImmediateScheduler;
        let context = BatchContext {
            batch_len: 1,
            batch_bytes: 16,
            oldest_wait: Duration::from_secs(60),
            queued_behind: 1000,
        };
        assert_eq!(scheduler.delay(&context), Duration::ZERO);
        assert!(scheduler.max_batch() >= 1);
        assert!(scheduler.max_batch_bytes() >= crate::frame::MAX_PAYLOAD);
        assert_eq!(scheduler.name(), "immediate");
    }
}

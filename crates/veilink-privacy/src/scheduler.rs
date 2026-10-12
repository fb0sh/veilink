//! The Strict Privacy send scheduler.
//!
//! Two goals, in order of priority:
//!
//! 1. **Do not add avoidable structure.** Sending each frame the instant it is produced creates a
//!    timing signature that mirrors the application's behaviour. Grouping frames into small batches
//!    and varying the gap between batches removes that signature's fine structure.
//! 2. **Never delay real traffic for the sake of the policy.** Latency is a cost the user pays, and
//!    a queue that never drains is indistinguishable from an outage. Every delay here is bounded,
//!    and a batch that has waited longer than the maximum is sent immediately.
//!
//! The policy is additionally *work-conserving*: when there is nothing queued behind the current
//! batch, there is no benefit to waiting, so the delay collapses to zero. Waiting only makes sense
//! when more frames are about to arrive, because that is when batching actually hides structure.

use std::time::Duration;

use veilink_protocol::scheduler::{BatchContext, SendScheduler};

/// Tunables for the scheduler. Not exposed in the configuration file in the first release.
#[derive(Debug, Clone, Copy)]
pub struct SchedulerConfig {
    /// Largest number of frames in one write.
    pub max_batch: usize,
    /// Largest number of plaintext bytes in one write.
    pub max_batch_bytes: usize,
    /// Base gap between batches.
    pub base_delay: Duration,
    /// Random extra gap, added on top of the base.
    pub jitter: Duration,
    /// Hard cap on any delay, whatever the policy computes.
    pub max_delay: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        SchedulerConfig {
            max_batch: 16,
            max_batch_bytes: 64 * 1024,
            base_delay: Duration::from_micros(200),
            jitter: Duration::from_millis(2),
            max_delay: Duration::from_millis(50),
        }
    }
}

/// The Strict Privacy scheduler.
#[derive(Debug)]
pub struct PrivacyScheduler {
    config: SchedulerConfig,
}

impl PrivacyScheduler {
    /// Creates a scheduler.
    pub fn new(config: SchedulerConfig) -> Self {
        PrivacyScheduler { config }
    }

    /// The default scheduler.
    pub fn strict() -> Self {
        PrivacyScheduler::new(SchedulerConfig::default())
    }

    /// The configuration in force.
    pub fn config(&self) -> SchedulerConfig {
        self.config
    }
}

impl SendScheduler for PrivacyScheduler {
    fn max_batch(&self) -> usize {
        self.config.max_batch.max(1)
    }

    fn max_batch_bytes(&self) -> usize {
        self.config.max_batch_bytes.max(1)
    }

    fn delay(&self, context: &BatchContext) -> Duration {
        // A message that has already waited too long goes now.
        if context.oldest_wait >= self.config.max_delay {
            return Duration::ZERO;
        }
        // Nothing queued behind this batch: waiting would only add latency, because there is
        // nothing to coalesce with.
        if context.queued_behind == 0 {
            return Duration::ZERO;
        }
        let jitter = veilink_crypto::random_below(self.config.jitter.as_micros().max(1) as u64)
            .map(Duration::from_micros)
            .unwrap_or(Duration::ZERO);
        (self.config.base_delay + jitter).min(self.config.max_delay)
    }

    fn name(&self) -> &'static str {
        "strict"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(queued_behind: usize, oldest_wait: Duration) -> BatchContext {
        BatchContext {
            batch_len: 1,
            batch_bytes: 1024,
            oldest_wait,
            queued_behind,
        }
    }

    #[test]
    fn an_empty_queue_is_never_delayed() {
        let scheduler = PrivacyScheduler::strict();
        assert_eq!(scheduler.delay(&context(0, Duration::ZERO)), Duration::ZERO);
    }

    #[test]
    fn delays_are_bounded_and_jittered() {
        let scheduler = PrivacyScheduler::strict();
        let config = scheduler.config();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..128 {
            let delay = scheduler.delay(&context(5, Duration::ZERO));
            assert!(delay <= config.max_delay);
            assert!(delay >= config.base_delay / 2);
            seen.insert(delay.as_micros());
        }
        assert!(seen.len() > 1, "the delay was not jittered");
    }

    #[test]
    fn a_starved_message_is_never_delayed() {
        let scheduler = PrivacyScheduler::strict();
        assert_eq!(
            scheduler.delay(&context(1000, scheduler.config().max_delay)),
            Duration::ZERO
        );
    }

    #[test]
    fn batching_bounds_are_positive() {
        let scheduler = PrivacyScheduler::strict();
        assert!(scheduler.max_batch() >= 1);
        assert!(scheduler.max_batch_bytes() >= 1024);
        assert_eq!(scheduler.name(), "strict");
    }

    #[test]
    fn a_misconfigured_policy_is_clamped_not_honoured() {
        let scheduler = PrivacyScheduler::new(SchedulerConfig {
            max_batch: 0,
            max_batch_bytes: 0,
            base_delay: Duration::from_secs(10),
            jitter: Duration::ZERO,
            max_delay: Duration::from_millis(5),
        });
        assert_eq!(scheduler.max_batch(), 1);
        assert_eq!(scheduler.max_batch_bytes(), 1);
        // The maximum still wins over an absurd base delay.
        assert!(scheduler.delay(&context(1, Duration::ZERO)) <= Duration::from_millis(5));
    }
}

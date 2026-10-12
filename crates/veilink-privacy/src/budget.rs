//! Resource budgets.
//!
//! Every privacy mechanism is a cost: padding spends bandwidth, cover traffic spends bandwidth and
//! money, batching spends latency. Each one therefore runs inside an explicit budget, and the budget
//! is enforced where the resource is actually consumed rather than being advisory.
//!
//! The budgets here are deliberately conservative and are **not** user-configurable in the first
//! release. A privacy feature that can be tuned into a denial of service, or into an unbounded VPS
//! bill, is worse than a slightly weaker one.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Fixed budget for one session.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    /// Maximum cover-traffic bytes per second, measured over a sliding window.
    pub cover_bytes_per_second: u64,
    /// Maximum total cover-traffic bytes over the lifetime of a session.
    pub cover_bytes_total: u64,
    /// Maximum number of queued outbound messages before the writer refuses more.
    pub max_queued_messages: usize,
    /// Maximum bytes of padding added per second.
    pub padding_bytes_per_second: u64,
    /// Maximum time any single frame may be delayed by the scheduler.
    pub max_scheduling_delay: Duration,
    /// How long a session must be idle before cover traffic starts.
    pub cover_idle_after: Duration,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            // Enough to blur an idle connection's timing without becoming a traffic generator.
            cover_bytes_per_second: 4 * 1024,
            // roughly 350 MiB per day at the cap, which is a deliberate ceiling on cost
            cover_bytes_total: 256 * 1024 * 1024,
            max_queued_messages: 512,
            padding_bytes_per_second: 4 * 1024 * 1024,
            max_scheduling_delay: Duration::from_millis(50),
            cover_idle_after: Duration::from_millis(750),
        }
    }
}

/// Errors raised when a budget is exceeded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BudgetError {
    /// The total cover-traffic allowance is exhausted.
    #[error("the cover-traffic budget of {limit} bytes is exhausted")]
    CoverTotalExhausted {
        /// The configured total.
        limit: u64,
    },
    /// The cover-traffic rate limit is saturated.
    #[error("the cover-traffic rate budget is saturated")]
    CoverRateExceeded,
    /// The padding allowance is saturated.
    #[error("the padding budget is saturated")]
    PaddingRateExceeded,
}

/// A sliding-window rate limiter plus a lifetime allowance.
#[derive(Debug)]
pub struct BudgetTracker {
    budget: Budget,
    /// Cover-traffic bytes granted in the current one-second window.
    cover_window: Mutex<(Instant, u64)>,
    /// Padding bytes granted in the current one-second window.
    ///
    /// Cover traffic and padding have separate windows: sharing one would let a burst of cover
    /// frames silently disable padding, which is exactly the kind of coupling that makes a budget
    /// hard to reason about.
    padding_window: Mutex<(Instant, u64)>,
    /// Lifetime cover bytes granted. This is the counter that protects against a runaway bill.
    cover_total: AtomicU64,
    /// Lifetime padding bytes granted.
    padding_total: AtomicU64,
}

impl BudgetTracker {
    /// Creates a tracker for `budget`.
    pub fn new(budget: Budget) -> Self {
        BudgetTracker {
            budget,
            cover_window: Mutex::new((Instant::now(), 0)),
            padding_window: Mutex::new((Instant::now(), 0)),
            cover_total: AtomicU64::new(0),
            padding_total: AtomicU64::new(0),
        }
    }

    /// The budget this tracker enforces.
    pub fn budget(&self) -> Budget {
        self.budget
    }

    /// Total cover-traffic bytes granted so far.
    pub fn cover_total(&self) -> u64 {
        self.cover_total.load(Ordering::Relaxed)
    }

    /// Total padding bytes granted so far.
    pub fn padding_total(&self) -> u64 {
        self.padding_total.load(Ordering::Relaxed)
    }

    /// Remaining lifetime cover allowance.
    pub fn cover_remaining(&self) -> u64 {
        self.budget
            .cover_bytes_total
            .saturating_sub(self.cover_total())
    }

    /// Requests permission to send `bytes` of cover traffic.
    ///
    /// Returns the number of bytes actually granted, which is zero when either the rate or the
    /// lifetime allowance is exhausted. Partial grants are intentional: it is better to send less
    /// cover traffic than to reject the request and leave the caller to retry in a loop.
    pub fn request_cover(&self, bytes: usize) -> Result<usize, BudgetError> {
        let remaining = self.cover_remaining();
        if remaining == 0 {
            return Err(BudgetError::CoverTotalExhausted {
                limit: self.budget.cover_bytes_total,
            });
        }
        let rate_grant = self.grant_rate(
            &self.cover_window,
            self.budget.cover_bytes_per_second,
            bytes as u64,
        );
        if rate_grant == 0 {
            return Err(BudgetError::CoverRateExceeded);
        }
        let granted = rate_grant.min(remaining) as usize;
        self.cover_total
            .fetch_add(granted as u64, Ordering::Relaxed);
        Ok(granted)
    }

    /// Requests permission to add `bytes` of padding.
    pub fn request_padding(&self, bytes: usize) -> Result<usize, BudgetError> {
        let granted = self.grant_rate(
            &self.padding_window,
            self.budget.padding_bytes_per_second,
            bytes as u64,
        );
        if granted == 0 {
            return Err(BudgetError::PaddingRateExceeded);
        }
        self.padding_total.fetch_add(granted, Ordering::Relaxed);
        Ok(granted as usize)
    }

    /// Grants up to `requested` bytes under a per-second window.
    fn grant_rate(&self, slot: &Mutex<(Instant, u64)>, limit: u64, requested: u64) -> u64 {
        let Ok(mut state) = slot.lock() else {
            return 0;
        };
        let now = Instant::now();
        if now.duration_since(state.0) >= Duration::from_secs(1) {
            *state = (now, 0);
        }
        let used = state.1;
        let available = limit.saturating_sub(used);
        let granted = available.min(requested);
        state.1 = used + granted;
        granted
    }
}

impl Default for BudgetTracker {
    fn default() -> Self {
        BudgetTracker::new(Budget::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rate_limiter_throttles_within_a_window() {
        let tracker = BudgetTracker::new(Budget {
            cover_bytes_per_second: 1000,
            cover_bytes_total: 1_000_000,
            ..Budget::default()
        });
        assert_eq!(tracker.request_cover(600).unwrap(), 600);
        // Only 400 bytes remain in this window.
        assert_eq!(tracker.request_cover(600).unwrap(), 400);
        assert_eq!(
            tracker.request_cover(1).unwrap_err(),
            BudgetError::CoverRateExceeded
        );
        assert_eq!(tracker.cover_total(), 1000);
    }

    #[test]
    fn the_lifetime_allowance_is_enforced() {
        let tracker = BudgetTracker::new(Budget {
            cover_bytes_per_second: u64::MAX,
            cover_bytes_total: 1500,
            ..Budget::default()
        });
        assert_eq!(tracker.request_cover(1000).unwrap(), 1000);
        // A partial grant is better than a refusal.
        assert_eq!(tracker.request_cover(1000).unwrap(), 500);
        assert_eq!(
            tracker.request_cover(1).unwrap_err(),
            BudgetError::CoverTotalExhausted { limit: 1500 }
        );
        assert_eq!(tracker.cover_remaining(), 0);
    }

    #[test]
    fn the_window_refills() {
        let tracker = BudgetTracker::new(Budget {
            cover_bytes_per_second: 100,
            cover_bytes_total: 1_000_000,
            ..Budget::default()
        });
        assert_eq!(tracker.request_cover(100).unwrap(), 100);
        assert!(tracker.request_cover(1).is_err());
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(tracker.request_cover(100).unwrap(), 100);
    }

    #[test]
    fn padding_and_cover_have_separate_allowances() {
        let tracker = BudgetTracker::new(Budget {
            padding_bytes_per_second: 100,
            cover_bytes_per_second: 100,
            ..Budget::default()
        });
        assert_eq!(tracker.request_padding(60).unwrap(), 60);
        assert_eq!(tracker.request_padding(60).unwrap(), 40);
        assert_eq!(
            tracker.request_padding(1).unwrap_err(),
            BudgetError::PaddingRateExceeded
        );
        // Padding does not consume the cover allowance, and vice versa.
        assert_eq!(tracker.cover_total(), 0);
        assert_eq!(tracker.request_cover(100).unwrap(), 100);
        // The padding window is still saturated, independently of the cover allowance.
        assert_eq!(
            tracker.request_padding(10).unwrap_err(),
            BudgetError::PaddingRateExceeded
        );
    }

    #[test]
    fn the_default_budget_is_bounded() {
        let budget = Budget::default();
        assert!(budget.cover_bytes_total > 0);
        assert!(budget.cover_bytes_total <= 1024 * 1024 * 1024);
        assert!(budget.cover_bytes_per_second <= 64 * 1024);
        assert!(budget.max_scheduling_delay <= Duration::from_millis(500));
        assert!(budget.max_queued_messages > 0);
    }
}

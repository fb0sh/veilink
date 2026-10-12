//! The client's and server's padding policy.
//!
//! The buckets themselves live in [`veilink_protocol::codec`], because the protocol layer has to
//! apply them; this module is the policy layer that decides how much padding a session is willing
//! to pay for, and it is where the resource budget is consulted.
//!
//! Padding is about *size*, and size is only one of the signals a passive observer has. Padding a
//! stream to fixed buckets hides how large a response was, within a bucket; it does not hide how
//! long the transfer took, how many frames it took, or that a transfer happened at all.

use std::sync::Arc;

use veilink_protocol::codec::{BucketedPadding, PaddingPolicy};

use crate::budget::BudgetTracker;

/// A padding policy that observes the resource budget.
///
/// When the padding allowance is saturated the policy falls back to the smallest bucket, which
/// still hides the exact length but costs less bandwidth. It never stops padding entirely: a policy
/// that silently disables itself is worse than one that degrades predictably.
#[derive(Debug)]
pub struct BudgetedPadding {
    inner: BucketedPadding,
    budget: Arc<BudgetTracker>,
    /// Bytes offered to the budget so far, for diagnostics.
    offered: std::sync::atomic::AtomicU64,
    /// Bytes the budget refused, for diagnostics.
    refused: std::sync::atomic::AtomicU64,
}

impl BudgetedPadding {
    /// Wraps a bucket policy with a budget.
    pub fn new(inner: BucketedPadding, budget: Arc<BudgetTracker>) -> Self {
        BudgetedPadding {
            inner,
            budget,
            offered: std::sync::atomic::AtomicU64::new(0),
            refused: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The default policy: the standard buckets under the default budget.
    pub fn with_default_budget() -> Self {
        BudgetedPadding::new(BucketedPadding::new(), Arc::new(BudgetTracker::default()))
    }

    /// Bytes of padding offered to the budget.
    pub fn offered(&self) -> u64 {
        self.offered.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Bytes of padding the budget refused.
    pub fn refused(&self) -> u64 {
        self.refused.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The smallest bucket this policy can produce.
    fn smallest_bucket(&self) -> usize {
        veilink_protocol::MAX_PAYLOAD.min(512)
    }
}

impl PaddingPolicy for BudgetedPadding {
    fn padded_len(&self, message_len: usize) -> usize {
        let wanted = self.inner.padded_len(message_len);
        let overhead = wanted.saturating_sub(message_len + 2);
        if overhead == 0 {
            return wanted;
        }
        self.offered
            .fetch_add(overhead as u64, std::sync::atomic::Ordering::Relaxed);
        match self.budget.request_padding(overhead) {
            Ok(granted) if granted >= overhead => wanted,
            _ => {
                self.refused
                    .fetch_add(overhead as u64, std::sync::atomic::Ordering::Relaxed);
                // Degrade to the smallest bucket rather than giving up on padding.
                let floor = self.smallest_bucket().max(message_len + 2);
                floor.min(veilink_protocol::MAX_PAYLOAD)
            }
        }
    }

    fn cover_len(&self, minimum: usize, maximum: usize) -> usize {
        self.inner.cover_len(minimum, maximum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::Budget;

    #[test]
    fn padding_is_applied_and_accounted() {
        let budget = Arc::new(BudgetTracker::new(Budget {
            padding_bytes_per_second: 1_000_000,
            ..Budget::default()
        }));
        let policy = BudgetedPadding::new(BucketedPadding::new(), budget.clone());
        let padded = policy.padded_len(100);
        assert_eq!(padded, 512, "100 bytes should land in the 512 byte bucket");
        assert_eq!(policy.offered(), 512 - 102);
        assert_eq!(policy.refused(), 0);
        assert_eq!(budget.padding_total(), (512 - 102) as u64);
    }

    #[test]
    fn padding_degrades_instead_of_disappearing_when_the_budget_is_gone() {
        let budget = Arc::new(BudgetTracker::new(Budget {
            // A hundred bytes per second cannot pay for a 8 KiB bucket.
            padding_bytes_per_second: 100,
            ..Budget::default()
        }));
        let policy = BudgetedPadding::new(BucketedPadding::new(), budget);
        // A message large enough that its bucket overhead exceeds the allowance.
        let message_len = 40_000;
        let padded = policy.padded_len(message_len);
        assert!(
            padded >= message_len + 2,
            "the length prefix must always fit: padded={padded}"
        );
        assert!(
            padded < 49_152,
            "the degraded policy must not exceed the requested bucket: padded={padded}"
        );
        assert!(policy.refused() > 0, "the refusal was not accounted");
    }

    #[test]
    fn small_messages_are_still_padded() {
        let policy = BudgetedPadding::with_default_budget();
        assert_eq!(policy.padded_len(1), 512);
        assert_eq!(policy.padded_len(400), 512);
        assert_eq!(policy.padded_len(600), 1024);
    }

    #[test]
    fn cover_lengths_stay_inside_the_requested_range() {
        let policy = BudgetedPadding::with_default_budget();
        for _ in 0..64 {
            let len = policy.cover_len(64, 1024);
            assert!(
                (64..=1024).contains(&len),
                "cover length {len} out of range"
            );
        }
    }
}

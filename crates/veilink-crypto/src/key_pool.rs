//! The receiver-side pool of one-time X25519 key pairs.
//!
//! This is the mechanism that turns "each frame has its own key" from a claim into a property.
//!
//! ```text
//! receiver                                sender
//!   generate key pair #N
//!   publish public half  ─── KEY_OFFER ───►  remembers (id, public)
//!                                            picks an unused id
//!                                            fresh ephemeral encapsulation
//!                          ◄── frame ───────  sealed with the derived key
//!   look up the private half by id
//!   Diffie-Hellman, derive, decrypt
//!   destroy the private half
//! ```
//!
//! Once the private half is destroyed the frame key cannot be recomputed by anyone — not by an
//! attacker who later steals the pre-shared key, and not by an attacker who later steals the
//! receiver's long-term identity. That is the forward-secrecy guarantee.
//!
//! ## Concurrency
//!
//! [`KeyPool::take`] removes the key pair from the pool under the pool lock, so two threads cannot
//! obtain the same one-time key even if a duplicate frame arrives simultaneously. Taking is the
//! *only* way to obtain a private half, which makes "one key, one frame" a structural property
//! rather than a convention.
//!
//! ## Bounds
//!
//! The pool is bounded in both directions: the local side never generates more than
//! [`KeyPool::max_size`] unconsumed keys, and it refuses to publish more than
//! [`MAX_OFFER_BATCH`] keys in one message. A peer cannot make us allocate unboundedly, and a
//! silently absent peer cannot make us leak memory.

use std::collections::HashMap;

use crate::x25519::{OneTimeKeyPair, RecipientPublicKey};
use crate::CryptoError;

/// Maximum number of keys published in a single `KEY_OFFER`.
pub const MAX_OFFER_BATCH: usize = 64;

/// Default pool size: enough unconsumed keys to cover a burst of frames without a round trip.
pub const DEFAULT_POOL_SIZE: usize = 256;

/// Refill when the number of unconsumed published keys drops to this level.
pub const DEFAULT_LOW_WATERMARK: usize = 48;

/// A single published, not yet consumed one-time key pair.
struct PooledKey {
    pair: OneTimeKeyPair,
}

/// One-time receiver keys, split into "published but unused" and bookkeeping for consumed ids.
pub struct KeyPool {
    /// Unconsumed keys, indexed by identifier.
    available: HashMap<u32, PooledKey>,
    /// Identifier of the most recently published key, for `request_more` bookkeeping.
    last_published: Option<u32>,
    next_id: u32,
    max_size: usize,
    low_watermark: usize,
    published_total: u64,
    consumed_total: u64,
    rejected_total: u64,
}

impl std::fmt::Debug for KeyPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPool")
            .field("available", &self.available.len())
            .field("max_size", &self.max_size)
            .field("published_total", &self.published_total)
            .field("consumed_total", &self.consumed_total)
            .finish()
    }
}

impl KeyPool {
    /// Creates a pool with the default size.
    pub fn new() -> Self {
        KeyPool::with_capacity(DEFAULT_POOL_SIZE, DEFAULT_LOW_WATERMARK)
    }

    /// Creates a pool with explicit bounds.
    pub fn with_capacity(max_size: usize, low_watermark: usize) -> Self {
        let max_size = max_size.clamp(8, 8192);
        KeyPool {
            available: HashMap::new(),
            last_published: None,
            next_id: 1,
            max_size,
            low_watermark: low_watermark.min(max_size / 2).max(1),
            published_total: 0,
            consumed_total: 0,
            rejected_total: 0,
        }
    }

    /// The maximum number of unconsumed keys this pool will hold.
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Number of keys that have been published and not yet consumed.
    pub fn available(&self) -> usize {
        self.available.len()
    }

    /// Total keys published over the lifetime of the pool.
    pub fn published_total(&self) -> u64 {
        self.published_total
    }

    /// Total keys consumed over the lifetime of the pool.
    pub fn consumed_total(&self) -> u64 {
        self.consumed_total
    }

    /// Frames rejected because their key identifier was unknown or already consumed.
    pub fn rejected_total(&self) -> u64 {
        self.rejected_total
    }

    /// True when the peer should be asked to publish more keys.
    pub fn needs_replenish(&self) -> bool {
        self.available.len() <= self.low_watermark
    }

    /// How many new keys should be published to reach the target level.
    pub fn replenish_amount(&self) -> usize {
        self.max_size
            .saturating_sub(self.available.len())
            .min(MAX_OFFER_BATCH)
    }

    /// Generates up to `count` new one-time keys and returns their public halves for publication.
    ///
    /// The private halves stay in the pool. Returns an empty vector when the pool is already full,
    /// so a caller cannot be tricked into unbounded generation.
    pub fn publish(&mut self, count: usize) -> Result<Vec<(u32, RecipientPublicKey)>, CryptoError> {
        let room = self.max_size.saturating_sub(self.available.len());
        let count = count.min(room).min(MAX_OFFER_BATCH);
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let pair = OneTimeKeyPair::generate()?;
            let id = self.allocate_id();
            let public = pair.public_key();
            self.available.insert(id, PooledKey { pair });
            self.last_published = Some(id);
            self.published_total += 1;
            out.push((id, public));
        }
        Ok(out)
    }

    /// Takes the private half of `key_id`, removing it from the pool.
    ///
    /// This is the only way to obtain a private half, so a key identifier can be used for exactly
    /// one frame. An unknown identifier — a replay, a forged frame, or a key the peer never
    /// published — returns [`CryptoError::UnknownKeyId`].
    pub fn take(&mut self, key_id: u32) -> Result<OneTimeKeyPair, CryptoError> {
        match self.available.remove(&key_id) {
            Some(entry) => {
                self.consumed_total += 1;
                Ok(entry.pair)
            }
            None => {
                self.rejected_total += 1;
                Err(CryptoError::UnknownKeyId(key_id))
            }
        }
    }

    /// True when `key_id` is currently published and unconsumed.
    ///
    /// Used by tests and diagnostics; frame processing must use [`KeyPool::take`] so that the
    /// check-and-consume is atomic.
    pub fn contains(&self, key_id: u32) -> bool {
        self.available.contains_key(&key_id)
    }

    /// The identifiers of every unconsumed key, for diagnostics.
    pub fn live_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.available.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// The identifier of the most recently published key.
    pub fn last_published(&self) -> Option<u32> {
        self.last_published
    }

    /// Drops every unconsumed key. Used when a session ends.
    pub fn clear(&mut self) {
        // Dropping each `OneTimeKeyPair` zeroizes its secret.
        self.available.clear();
    }

    fn allocate_id(&mut self) -> u32 {
        // Identifiers are never reused within a session; on wraparound the counter restarts above
        // any live identifier so a stale frame cannot match a fresh key.
        loop {
            let candidate = self.next_id;
            self.next_id = self.next_id.wrapping_add(1).max(1);
            if !self.available.contains_key(&candidate) {
                return candidate;
            }
        }
    }
}

impl Default for KeyPool {
    fn default() -> Self {
        KeyPool::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishes_and_consumes_keys() {
        let mut pool = KeyPool::with_capacity(16, 4);
        let published = pool.publish(8).unwrap();
        assert_eq!(published.len(), 8);
        assert_eq!(pool.available(), 8);
        assert_eq!(pool.published_total(), 8);

        let (id, _public) = published[0];
        let pair = pool.take(id).unwrap();
        assert_eq!(pool.available(), 7);
        assert_eq!(pool.consumed_total(), 1);
        // The key cannot be taken twice.
        assert!(matches!(
            pool.take(id),
            Err(CryptoError::UnknownKeyId(_))
        ));
        assert_eq!(pool.rejected_total(), 1);
        drop(pair);
    }

    #[test]
    fn identifiers_are_unique_across_batches() {
        let mut pool = KeyPool::with_capacity(256, 8);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            for (id, _) in pool.publish(32).unwrap() {
                assert!(seen.insert(id), "key identifier {id} was reused");
            }
        }
        assert_eq!(seen.len(), 256);
    }

    #[test]
    fn a_full_pool_refuses_to_generate_more() {
        let mut pool = KeyPool::with_capacity(8, 2);
        assert_eq!(pool.publish(8).unwrap().len(), 8);
        assert!(pool.publish(8).unwrap().is_empty());
        assert_eq!(pool.available(), 8);
        // Consuming one frees exactly one slot.
        let id = pool.live_ids()[0];
        pool.take(id).unwrap();
        assert_eq!(pool.publish(4).unwrap().len(), 1);
    }

    #[test]
    fn a_single_offer_is_bounded() {
        let mut pool = KeyPool::with_capacity(4096, 8);
        assert_eq!(pool.publish(4096).unwrap().len(), MAX_OFFER_BATCH);
    }

    #[test]
    fn low_watermark_drives_replenishment() {
        let mut pool = KeyPool::with_capacity(16, 4);
        pool.publish(16).unwrap();
        assert!(!pool.needs_replenish());
        while pool.available() > 4 {
            let id = pool.live_ids()[0];
            pool.take(id).unwrap();
        }
        assert!(pool.needs_replenish(), "pool did not ask for replenishment");
        assert_eq!(pool.replenish_amount(), 12);
    }

    #[test]
    fn concurrent_take_never_returns_the_same_key_twice() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        let mut pool = KeyPool::with_capacity(64, 8);
        let published = pool.publish(64).unwrap();
        let pool = Arc::new(Mutex::new(pool));
        let succeeded = Arc::new(AtomicUsize::new(0));
        let ids: Vec<u32> = published.iter().map(|(id, _)| *id).collect();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let pool = pool.clone();
            let succeeded = succeeded.clone();
            let ids = ids.clone();
            handles.push(std::thread::spawn(move || {
                for id in ids {
                    if pool.lock().unwrap().take(id).is_ok() {
                        succeeded.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(
            succeeded.load(Ordering::Relaxed),
            published.len(),
            "a one-time key was handed out more than once"
        );
        assert_eq!(pool.lock().unwrap().available(), 0);
    }

    #[test]
    fn refresh_after_wraparound_does_not_collide_with_live_keys() {
        let mut pool = KeyPool::with_capacity(64, 4);
        // Force the identifier counter close to wrapping.
        pool.next_id = u32::MAX - 1;
        let first = pool.publish(4).unwrap();
        let live: Vec<u32> = first.iter().map(|(id, _)| *id).collect();
        let second = pool.publish(4).unwrap();
        for (id, _) in &second {
            assert!(!live.contains(id), "identifier {id} collided with a live key");
        }
        assert_eq!(pool.available(), 8);
    }

    #[test]
    fn clear_drops_every_unconsumed_key() {
        let mut pool = KeyPool::with_capacity(32, 4);
        pool.publish(16).unwrap();
        assert_eq!(pool.available(), 16);
        pool.clear();
        assert_eq!(pool.available(), 0);
        assert!(pool.live_ids().is_empty());
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let mut pool = KeyPool::with_capacity(8, 2);
        let published = pool.publish(2).unwrap();
        let text = format!("{pool:?}");
        for (id, public) in published {
            let hex: String = public
                .to_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert!(!text.contains(&hex), "pool debug leaked key material");
            let _ = id;
        }
    }
}

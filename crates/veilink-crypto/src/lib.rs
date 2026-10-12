//! # veilink-crypto
//!
//! Cryptographic core of the Veilink protocol (`VLP/1`).
//!
//! Nothing in this crate invents a primitive. Every operation is delegated to an audited library:
//! `RustCrypto` for AES-GCM, ChaCha20-Poly1305, HKDF, SHA-256 and HMAC, and `dalek` for X25519.
//! What this crate does own is the *composition*: which keys exist, what they are bound to, when
//! they are destroyed, and what an attacker learns when one of them leaks.
//!
//! ## Modules
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`rng`] | the only source of randomness; fails closed |
//! | [`psk`] | the operator's pre-shared key and purpose-bound derivations |
//! | [`aead`] | the three permitted AEAD algorithms behind one interface |
//! | [`x25519`] | ephemeral sender keys, one-time receiver keys, long-term identity |
//! | [`kdf`] | the transcript-bound key schedule and the control-channel ratchet |
//! | [`epoch`] | directions, sequence numbers and replay rejection |
//! | [`key_pool`] | the receiver's one-time key pool |
//! | [`handshake`] | the PSK-bound, channel-binding authentication handshake |
//! | [`identity`] | the server's persisted long-term identity |
//!
//! ## The security claim in one paragraph
//!
//! The two peers authenticate each other with a pre-shared key and bind that authentication to the
//! outer TLS session through the TLS exporter, so an unauthenticated peer, a relay and a replayed
//! handshake all fail before a single proxy request is read. Every business frame is then sealed
//! with a key derived from a fresh X25519 exchange against a one-time key pair belonging to the
//! receiver; the receiver destroys its private half as soon as the frame is decrypted. A frame's
//! key therefore cannot be recomputed after the fact by anyone — not by an attacker who later
//! obtains the pre-shared key, and not by one who later obtains the server's long-term identity.
//!
//! ## What this crate does *not* claim
//!
//! * Software key erasure is best effort. `zeroize` overwrites the memory it controls, but a memory
//!   snapshot, a swap file, a hibernation image or a hypervisor can capture secrets before they are
//!   erased. Forward secrecy holds only after erasure has actually happened.
//! * The pre-shared key authenticates; it does not hide. An attacker who holds it can impersonate
//!   the server for *future* sessions. It cannot decrypt recorded frames, because those keys came
//!   from erased ephemeral material.
//! * Nothing here hides traffic patterns. See `docs/privacy.md`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aead;
pub mod epoch;
pub mod handshake;
pub mod identity;
pub mod kdf;
pub mod key_pool;
pub mod psk;
pub mod rng;
pub mod x25519;

pub use aead::{AeadKey, AlgorithmId, AlgorithmSet, ALL_ALGORITHMS, NONCE_LEN, TAG_LEN};
pub use epoch::{Direction, RecvSequence, SendSequence, SequenceMode};
pub use handshake::{
    keys_equal, run_handshake_in_memory, ClientHandshake, ClientHello, HandshakeState,
    ServerHandshake, ServerHello, AUTH_CONFIRM_LEN, CLIENT_HELLO_LEN, PROTOCOL_VERSION,
    SERVER_HELLO_LEN,
};
pub use identity::{
    fingerprint_matches_pin, fingerprint_of, parse_fingerprint_pin, Identity, IdentityError,
};
pub use kdf::{
    derive_frame_material, derive_handshake_keys, select_algorithm, ControlChain, FrameKeyContext,
    HandshakeKeys, Transcript, EXPORTER_LABEL, HASH_LEN, PROTOCOL_LABEL,
};
pub use key_pool::{KeyPool, DEFAULT_LOW_WATERMARK, DEFAULT_POOL_SIZE, MAX_OFFER_BATCH};
pub use psk::{derive_key, extract_key, DerivedKey, Psk, PskError, MIN_PSK_LEN};
pub use rng::{fill_random, random_array, random_below, random_nonzero_u64, random_u64, RngError};
pub use x25519::{IdentitySecret, OneTimeKeyPair, RecipientPublicKey, SenderEphemeral, X25519_LEN};

/// Errors raised by the cryptographic layer.
///
/// The variants are deliberately coarse. A caller should not be able to distinguish "wrong key"
/// from "tampered ciphertext" — both are [`CryptoError::AuthenticationFailed`] — so that error
/// handling cannot become an oracle.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// An algorithm identifier outside the allow-list.
    #[error("unsupported AEAD algorithm identifier {0}")]
    UnsupportedAlgorithm(u8),
    /// A key whose length does not match its algorithm.
    #[error("{algorithm} needs a {expected}-byte key, got {actual}")]
    InvalidKeyLength {
        /// Algorithm name.
        algorithm: &'static str,
        /// Required length.
        expected: usize,
        /// Observed length.
        actual: usize,
    },
    /// A tag verification failed, or the plaintext was not authentic.
    #[error(
        "authentication failed: the frame was modified, forged, or belongs to another session"
    )]
    AuthenticationFailed,
    /// An input was shorter than the fixed structure requires.
    #[error("truncated input: needed {needed} bytes, found {actual}")]
    Truncated {
        /// Required length.
        needed: usize,
        /// Observed length.
        actual: usize,
    },
    /// A frame exceeded the strict maximum size.
    #[error("frame of {0} bytes exceeds the maximum accepted size")]
    FrameTooLarge(usize),
    /// A peer public key was a low-order point.
    #[error("peer public key is not contributory (low-order point), refusing to derive a key")]
    NonContributory,
    /// The operating system RNG failed.
    #[error(transparent)]
    Rng(#[from] RngError),
    /// The pre-shared key was not usable.
    #[error(transparent)]
    Psk(#[from] PskError),
    /// The one-time key pool had no room.
    #[error("the one-time key pool is exhausted")]
    KeyPoolExhausted,
    /// A frame referenced a one-time key that is not available.
    #[error("unknown or already consumed one-time key identifier {0}")]
    UnknownKeyId(u32),
    /// A handshake step failed.
    #[error("handshake failed: {0}")]
    Handshake(String),
    /// A frame was replayed, reordered or skipped.
    #[error("frame sequence {got} is not acceptable (expected at least {expected})")]
    Replay {
        /// Sequence number received.
        got: u64,
        /// Sequence number expected.
        expected: u64,
    },
    /// A protocol invariant was violated.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// A required piece of key material was not available yet.
    #[error("key material is not available yet: {0}")]
    MissingMaterial(&'static str),
}

impl CryptoError {
    /// True when the error indicates an authentication failure rather than a local bug.
    ///
    /// Used by the transport to decide whether to count an authentication failure in the statistics
    /// and whether the peer should be treated as hostile.
    pub fn is_authentication_failure(&self) -> bool {
        matches!(
            self,
            CryptoError::AuthenticationFailed
                | CryptoError::Psk(_)
                | CryptoError::Handshake(_)
                | CryptoError::NonContributory
                | CryptoError::UnknownKeyId(_)
                | CryptoError::Replay { .. }
                | CryptoError::UnsupportedAlgorithm(_)
                | CryptoError::InvalidKeyLength { .. }
        )
    }
}

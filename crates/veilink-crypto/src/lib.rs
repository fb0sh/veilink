//! # veilink-crypto
//!
//! Cryptographic core of the Veilink protocol (`VLP/1`).
//!
//! The crate is organised around a small number of explicit building blocks:
//!
//! * [`rng`] — the only source of randomness; fails closed when the OS CSPRNG is unavailable.
//! * [`psk`] — the operator-supplied 256-bit pre-shared authentication key and its purpose-bound
//!   HKDF derivations.
//! * [`aead`] — the three permitted AEAD algorithms (`AES-256-GCM`, `ChaCha20-Poly1305`,
//!   `AES-128-GCM`) behind one constant-time, algorithm-agile interface.
//! * [`kdf`] — the transcript-bound key schedule that mixes the PSK, the TLS channel binding value
//!   and per-frame ephemeral material.
//! * [`x25519`] — ephemeral Diffie-Hellman primitives.
//! * [`epoch`] — sender and receiver frame counters and replay/duplicate rejection.
//! * [`key_pool`] — the receiver-side pool of one-time X25519 key pairs that gives every business
//!   frame its own key and provides forward secrecy after erasure.
//! * [`handshake`] — the PSK-bound, channel-binding authentication handshake.
//!
//! ## Security posture
//!
//! * No cryptographic primitive is implemented here; everything is delegated to audited crates
//!   (`RustCrypto`, `dalek`).
//! * Secret material is held in [`zeroize`] containers and never rendered by `Debug`.
//! * Algorithm identifiers are validated against a fixed allow-list before use.
//! * Key material is never reused across sessions, directions or frames.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod psk;
pub mod rng;

pub use psk::{derive_key, extract_key, DerivedKey, Psk, PskError, MIN_PSK_LEN};
pub use rng::{fill_random, random_array, random_below, random_nonzero_u64, random_u64, RngError};

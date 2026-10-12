//! X25519 ephemeral and one-time key pairs.
//!
//! Two kinds of key pair exist in `VLP/1`:
//!
//! * **Sender ephemeral keys** — generated fresh for every business frame, used once, then dropped.
//!   Their public half travels in the frame header so the receiver can perform the Diffie-Hellman
//!   step.
//! * **Receiver one-time keys** — generated in batches by the receiving side and published inside
//!   authenticated `KEY_OFFER` messages. The sender picks one, encapsulates against it, and the
//!   receiver destroys the private half as soon as the frame has been decrypted.
//!
//! The second kind is what makes forward secrecy real rather than nominal: after the private half
//! has been erased, the frame's key cannot be recomputed even by someone who later obtains the
//! receiver's long-term identity, the pre-shared key, or the whole control-channel key chain.
//!
//! Low-order peer public keys are rejected outright. Without that check, an attacker could force a
//! shared secret of zero and the resulting key would be predictable.

use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroizing;

use crate::rng::random_array;
use crate::CryptoError;

/// Length of an X25519 public key or shared secret.
pub const X25519_LEN: usize = 32;

/// A fresh, single-use sender key pair.
pub struct SenderEphemeral {
    secret: StaticSecret,
    public: PublicKey,
}

impl std::fmt::Debug for SenderEphemeral {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SenderEphemeral(<redacted>)")
    }
}

impl SenderEphemeral {
    /// Generates a key pair from the operating system CSPRNG.
    ///
    /// The seed comes from [`crate::rng`] rather than from a library-internal RNG so that a failure
    /// of the operating system entropy source propagates as an error instead of a panic, and so
    /// that there is exactly one place in the codebase that touches the CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(random_array::<32>()?);
        let secret = StaticSecret::from(*seed);
        let public = PublicKey::from(&secret);
        Ok(SenderEphemeral { secret, public })
    }

    /// The public half, to be placed in the frame header.
    pub fn public_bytes(&self) -> [u8; X25519_LEN] {
        self.public.to_bytes()
    }

    /// Performs the Diffie-Hellman step against the recipient's public key.
    pub fn encapsulate(self, recipient: &RecipientPublicKey) -> Result<SharedSecret, CryptoError> {
        let peer = PublicKey::from(recipient.0);
        let shared = self.secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(CryptoError::NonContributory);
        }
        Ok(shared)
    }
}

/// A receiver public key as published in a `KEY_OFFER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientPublicKey([u8; X25519_LEN]);

impl RecipientPublicKey {
    /// Wraps 32 bytes from the wire, rejecting the all-zero key.
    pub fn from_bytes(bytes: [u8; X25519_LEN]) -> Result<Self, CryptoError> {
        if bytes.iter().all(|b| *b == 0) {
            return Err(CryptoError::Protocol(
                "peer published an all-zero public key".to_string(),
            ));
        }
        Ok(RecipientPublicKey(bytes))
    }

    /// The raw bytes.
    pub fn to_bytes(self) -> [u8; X25519_LEN] {
        self.0
    }
}

/// A one-time receiver key pair held in the key pool.
pub struct OneTimeKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl std::fmt::Debug for OneTimeKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OneTimeKeyPair(<redacted>)")
    }
}

impl OneTimeKeyPair {
    /// Generates a one-time key pair from the operating system CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(random_array::<32>()?);
        let secret = StaticSecret::from(*seed);
        let public = PublicKey::from(&secret);
        Ok(OneTimeKeyPair { secret, public })
    }

    /// The public half to publish.
    pub fn public_key(&self) -> RecipientPublicKey {
        RecipientPublicKey(self.public.to_bytes())
    }

    /// Completes the Diffie-Hellman step for an incoming frame.
    ///
    /// Consumes the key pair: the caller must not be able to use it again, which is what guarantees
    /// one frame per one-time key.
    pub fn decapsulate(self, sender_public: &[u8; X25519_LEN]) -> Result<SharedSecret, CryptoError> {
        let public = RecipientPublicKey::from_bytes(*sender_public)?;
        let peer = PublicKey::from(public.0);
        let shared = self.secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(CryptoError::NonContributory);
        }
        Ok(shared)
    }
}

/// A long-term identity key pair, used to generate and persist the server's TLS identity.
///
/// It is deliberately *not* used for frame encryption. Losing it must not expose any recorded
/// frame, which is exactly what the one-time key pool guarantees.
pub struct IdentitySecret {
    secret: StaticSecret,
    public: PublicKey,
}

impl std::fmt::Debug for IdentitySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentitySecret(<redacted>)")
    }
}

impl IdentitySecret {
    /// Generates a new identity.
    pub fn generate() -> Result<Self, CryptoError> {
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(random_array::<32>()?);
        Self::from_bytes(*seed)
    }

    /// Reconstitutes an identity from stored bytes.
    pub fn from_bytes(seed: [u8; 32]) -> Result<Self, CryptoError> {
        if seed.iter().all(|b| *b == 0) {
            return Err(CryptoError::Protocol(
                "identity seed must not be all zeroes".to_string(),
            ));
        }
        let secret = StaticSecret::from(seed);
        let public = PublicKey::from(&secret);
        Ok(IdentitySecret { secret, public })
    }

    /// The private bytes, for persistence. Treat as secret.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// The public identity.
    pub fn public_bytes(&self) -> [u8; X25519_LEN] {
        self.public.to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_and_receiver_agree_on_the_shared_secret() {
        let receiver = OneTimeKeyPair::generate().unwrap();
        let public = receiver.public_key();
        let sender = SenderEphemeral::generate().unwrap();
        let sender_public = sender.public_bytes();

        let sender_shared = sender.encapsulate(&public).unwrap();
        let receiver_shared = receiver.decapsulate(&sender_public).unwrap();
        assert_eq!(sender_shared.as_bytes(), receiver_shared.as_bytes());
        assert_ne!(sender_shared.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn each_ephemeral_produces_a_different_secret() {
        let receiver = OneTimeKeyPair::generate().unwrap();
        let public = receiver.public_key();
        let first = SenderEphemeral::generate()
            .unwrap()
            .encapsulate(&public)
            .unwrap();
        let second = SenderEphemeral::generate()
            .unwrap()
            .encapsulate(&public)
            .unwrap();
        assert_ne!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn public_keys_are_unique_per_generation() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let key = OneTimeKeyPair::generate().unwrap();
            assert!(seen.insert(key.public_key().to_bytes()));
        }
    }

    #[test]
    fn rejects_low_order_and_zero_public_keys() {
        // The all-zero public key is the canonical low-order point.
        assert!(RecipientPublicKey::from_bytes([0u8; 32]).is_err());

        let receiver = OneTimeKeyPair::generate().unwrap();
        let zero_sender = [0u8; 32];
        assert!(matches!(
            receiver.decapsulate(&zero_sender),
            Err(CryptoError::Protocol(_))
        ));

        // A low-order point that is not all zeroes must also be refused.
        let mut low_order = [0u8; 32];
        low_order[0] = 1; // the identity element encoding
        let receiver = OneTimeKeyPair::generate().unwrap();
        assert!(matches!(
            receiver.decapsulate(&low_order),
            Err(CryptoError::NonContributory)
        ));
    }

    #[test]
    fn identity_is_stable_across_serialisation() {
        let identity = IdentitySecret::generate().unwrap();
        let bytes = identity.to_bytes();
        let restored = IdentitySecret::from_bytes(*bytes).unwrap();
        assert_eq!(identity.public_bytes(), restored.public_bytes());
        assert!(IdentitySecret::from_bytes([0u8; 32]).is_err());
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let receiver = OneTimeKeyPair::generate().unwrap();
        let public_hex: String = receiver
            .public_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(format!("{receiver:?}"), "OneTimeKeyPair(<redacted>)");
        assert!(!format!("{receiver:?}").contains(&public_hex));

        let identity = IdentitySecret::generate().unwrap();
        assert_eq!(format!("{identity:?}"), "IdentitySecret(<redacted>)");

        let sender = SenderEphemeral::generate().unwrap();
        assert_eq!(format!("{sender:?}"), "SenderEphemeral(<redacted>)");
    }
}

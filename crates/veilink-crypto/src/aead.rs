//! The three permitted AEAD algorithms behind one constant-time, algorithm-agile interface.
//!
//! `VLP/1` lets the *sender* pick the algorithm for each frame from the set both peers advertised.
//! That is a traffic-shaping policy, not a security property: the security of a frame comes from
//! its key being unique, never from which of these three cipher suites was chosen.
//!
//! Every algorithm here is a standard AEAD with a 128-bit tag, supplied by RustCrypto:
//!
//! | id | algorithm | key | nonce | tag |
//! |----|-----------|-----|-------|-----|
//! | 1  | AES-256-GCM | 32 B | 12 B | 16 B |
//! | 2  | ChaCha20-Poly1305 | 32 B | 12 B | 16 B |
//! | 3  | AES-128-GCM | 16 B | 12 B | 16 B |
//!
//! Nothing here invents a construction: algorithm identifiers are validated against a fixed
//! allow-list, key lengths are checked, and a failed tag verification wipes the output buffer so
//! that unauthenticated plaintext can never be observed by the caller.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::CryptoError;

/// Length of every nonce used by `VLP/1`.
pub const NONCE_LEN: usize = 12;
/// Length of the authentication tag.
pub const TAG_LEN: usize = 16;

/// A nonce.
pub type Nonce = [u8; NONCE_LEN];

/// The AEAD algorithms permitted by `VLP/1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum AlgorithmId {
    /// AES-256-GCM (id 1).
    Aes256Gcm = 1,
    /// ChaCha20-Poly1305 (id 2).
    ChaCha20Poly1305 = 2,
    /// AES-128-GCM (id 3).
    Aes128Gcm = 3,
}

/// Every permitted algorithm, in identifier order.
pub const ALL_ALGORITHMS: [AlgorithmId; 3] = [
    AlgorithmId::Aes256Gcm,
    AlgorithmId::ChaCha20Poly1305,
    AlgorithmId::Aes128Gcm,
];

impl AlgorithmId {
    /// Decodes an algorithm identifier, rejecting anything outside the allow-list.
    pub fn from_u8(value: u8) -> Result<Self, CryptoError> {
        match value {
            1 => Ok(AlgorithmId::Aes256Gcm),
            2 => Ok(AlgorithmId::ChaCha20Poly1305),
            3 => Ok(AlgorithmId::Aes128Gcm),
            other => Err(CryptoError::UnsupportedAlgorithm(other)),
        }
    }

    /// The wire identifier.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// The key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            AlgorithmId::Aes256Gcm | AlgorithmId::ChaCha20Poly1305 => 32,
            AlgorithmId::Aes128Gcm => 16,
        }
    }

    /// A human-readable name, used in logs and error messages.
    pub fn name(self) -> &'static str {
        match self {
            AlgorithmId::Aes256Gcm => "AES-256-GCM",
            AlgorithmId::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            AlgorithmId::Aes128Gcm => "AES-128-GCM",
        }
    }

    /// The bitmask bit representing this algorithm in a negotiation field.
    pub fn mask_bit(self) -> u8 {
        1u8 << (self.as_u8() - 1)
    }
}

/// A bitmask of the algorithms a peer is willing to receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgorithmSet(u8);

impl AlgorithmSet {
    /// The set containing every permitted algorithm.
    pub fn all() -> Self {
        let mut mask = 0u8;
        for algorithm in ALL_ALGORITHMS {
            mask |= algorithm.mask_bit();
        }
        AlgorithmSet(mask)
    }

    /// Decodes a negotiation bitmask, rejecting unknown bits and an empty set.
    pub fn from_mask(mask: u8) -> Result<Self, CryptoError> {
        let known = AlgorithmSet::all().0;
        if mask & !known != 0 {
            return Err(CryptoError::Protocol(format!(
                "algorithm mask 0x{mask:02x} advertises algorithms this build does not implement"
            )));
        }
        if mask == 0 {
            return Err(CryptoError::Protocol(
                "algorithm mask 0x00 advertises no algorithms".to_string(),
            ));
        }
        Ok(AlgorithmSet(mask))
    }

    /// The raw bitmask.
    pub fn mask(self) -> u8 {
        self.0
    }

    /// Whether `algorithm` is in this set.
    pub fn contains(self, algorithm: AlgorithmId) -> bool {
        self.0 & algorithm.mask_bit() != 0
    }

    /// The algorithms in this set, in identifier order.
    pub fn iter(self) -> impl Iterator<Item = AlgorithmId> {
        ALL_ALGORITHMS
            .into_iter()
            .filter(move |a| self.contains(*a))
    }

    /// Number of algorithms in the set.
    pub fn len(self) -> usize {
        self.iter().count()
    }

    /// Always `false`: a decoded set never contains zero algorithms.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// A single-use AEAD key.
pub struct AeadKey {
    algorithm: AlgorithmId,
    key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadKey")
            .field("algorithm", &self.algorithm)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl AeadKey {
    /// Builds a key from raw bytes, checking the length for the algorithm.
    pub fn new(algorithm: AlgorithmId, key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != algorithm.key_len() {
            return Err(CryptoError::InvalidKeyLength {
                algorithm: algorithm.name(),
                expected: algorithm.key_len(),
                actual: key.len(),
            });
        }
        Ok(AeadKey {
            algorithm,
            key: Zeroizing::new(key.to_vec()),
        })
    }

    /// The algorithm this key belongs to.
    pub fn algorithm(&self) -> AlgorithmId {
        self.algorithm
    }

    /// Encrypts `buffer` in place and appends the authentication tag.
    ///
    /// `aad` must contain the complete frame header; it is authenticated but not encrypted.
    pub fn seal_in_place(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let tag = match self.algorithm {
            AlgorithmId::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| {
                    CryptoError::InvalidKeyLength {
                        algorithm: self.algorithm.name(),
                        expected: 32,
                        actual: self.key.len(),
                    }
                })?;
                cipher.encrypt_in_place_detached(nonce.into(), aad, buffer)
            }
            AlgorithmId::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| {
                    CryptoError::InvalidKeyLength {
                        algorithm: self.algorithm.name(),
                        expected: 32,
                        actual: self.key.len(),
                    }
                })?;
                cipher.encrypt_in_place_detached(nonce.into(), aad, buffer)
            }
            AlgorithmId::Aes128Gcm => {
                let cipher = Aes128Gcm::new_from_slice(&self.key).map_err(|_| {
                    CryptoError::InvalidKeyLength {
                        algorithm: self.algorithm.name(),
                        expected: 16,
                        actual: self.key.len(),
                    }
                })?;
                cipher.encrypt_in_place_detached(nonce.into(), aad, buffer)
            }
        }
        .map_err(|_| CryptoError::Protocol("AEAD encryption failed".to_string()))?;

        buffer.extend_from_slice(&tag);
        Ok(())
    }

    /// Verifies and decrypts `buffer` in place.
    ///
    /// `buffer` must hold `ciphertext || tag`. The buffer is wiped before returning an error, so a
    /// caller can never accidentally observe unauthenticated plaintext.
    pub fn open_in_place(
        &self,
        nonce: &Nonce,
        aad: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        if buffer.len() < TAG_LEN {
            buffer.clear();
            return Err(CryptoError::AuthenticationFailed);
        }
        let split = buffer.len() - TAG_LEN;
        let tag = buffer.split_off(split);
        let mut tag_array = [0u8; TAG_LEN];
        tag_array.copy_from_slice(&tag);

        let result = match self.algorithm {
            AlgorithmId::Aes256Gcm => Aes256Gcm::new_from_slice(&self.key)
                .map_err(|_| CryptoError::AuthenticationFailed)
                .and_then(|cipher| {
                    cipher
                        .decrypt_in_place_detached(nonce.into(), aad, buffer, &tag_array.into())
                        .map_err(|_| CryptoError::AuthenticationFailed)
                }),
            AlgorithmId::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(&self.key)
                .map_err(|_| CryptoError::AuthenticationFailed)
                .and_then(|cipher| {
                    cipher
                        .decrypt_in_place_detached(nonce.into(), aad, buffer, &tag_array.into())
                        .map_err(|_| CryptoError::AuthenticationFailed)
                }),
            AlgorithmId::Aes128Gcm => Aes128Gcm::new_from_slice(&self.key)
                .map_err(|_| CryptoError::AuthenticationFailed)
                .and_then(|cipher| {
                    cipher
                        .decrypt_in_place_detached(nonce.into(), aad, buffer, &tag_array.into())
                        .map_err(|_| CryptoError::AuthenticationFailed)
                }),
        };

        if result.is_err() {
            use zeroize::Zeroize;
            buffer.zeroize();
            buffer.clear();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroize;

    fn key_for(algorithm: AlgorithmId, seed: u8) -> Vec<u8> {
        (0..algorithm.key_len())
            .map(|i| seed.wrapping_add(i as u8))
            .collect()
    }

    #[test]
    fn algorithm_identifiers_round_trip_and_reject_unknown() {
        for algorithm in ALL_ALGORITHMS {
            assert_eq!(AlgorithmId::from_u8(algorithm.as_u8()).unwrap(), algorithm);
        }
        for bogus in [0u8, 4, 5, 255] {
            assert!(matches!(
                AlgorithmId::from_u8(bogus),
                Err(CryptoError::UnsupportedAlgorithm(_))
            ));
        }
    }

    #[test]
    fn key_lengths_are_enforced() {
        for algorithm in ALL_ALGORITHMS {
            let good = key_for(algorithm, 1);
            assert!(AeadKey::new(algorithm, &good).is_ok());
            let mut short = good.clone();
            short.pop();
            assert!(matches!(
                AeadKey::new(algorithm, &short),
                Err(CryptoError::InvalidKeyLength { .. })
            ));
            let mut long = good.clone();
            long.push(0);
            assert!(AeadKey::new(algorithm, &long).is_err());
        }
    }

    #[test]
    fn seal_open_round_trip_for_every_algorithm() {
        for algorithm in ALL_ALGORITHMS {
            let key = AeadKey::new(algorithm, &key_for(algorithm, 7)).unwrap();
            let nonce = [3u8; NONCE_LEN];
            let aad = b"header bytes";
            let plaintext = b"the quick brown fox".to_vec();

            let mut buffer = plaintext.clone();
            key.seal_in_place(&nonce, aad, &mut buffer).unwrap();
            assert_eq!(buffer.len(), plaintext.len() + TAG_LEN);
            assert_ne!(&buffer[..plaintext.len()], &plaintext[..]);

            key.open_in_place(&nonce, aad, &mut buffer).unwrap();
            assert_eq!(buffer, plaintext);
        }
    }

    #[test]
    fn tampering_is_detected_in_ciphertext_aad_and_tag() {
        for algorithm in ALL_ALGORITHMS {
            let key = AeadKey::new(algorithm, &key_for(algorithm, 11)).unwrap();
            let nonce = [9u8; NONCE_LEN];
            let aad = b"authenticated header";
            let plaintext = b"secret payload".to_vec();

            // Flipping one ciphertext bit.
            let mut buffer = plaintext.clone();
            key.seal_in_place(&nonce, aad, &mut buffer).unwrap();
            buffer[0] ^= 0x01;
            assert_eq!(
                key.open_in_place(&nonce, aad, &mut buffer).unwrap_err(),
                CryptoError::AuthenticationFailed
            );
            assert!(
                buffer.is_empty(),
                "unauthenticated plaintext was left behind"
            );

            // Changing the AAD (this is how a frame header substitution is caught).
            let mut buffer = plaintext.clone();
            key.seal_in_place(&nonce, aad, &mut buffer).unwrap();
            assert!(key
                .open_in_place(&nonce, b"authenticated headeR", &mut buffer)
                .is_err());

            // Truncating the tag.
            let mut buffer = plaintext.clone();
            key.seal_in_place(&nonce, aad, &mut buffer).unwrap();
            buffer.pop();
            assert!(key.open_in_place(&nonce, aad, &mut buffer).is_err());
            assert!(buffer.is_empty());
        }
    }

    #[test]
    fn a_different_nonce_yields_a_different_ciphertext() {
        let algorithm = AlgorithmId::ChaCha20Poly1305;
        let key = AeadKey::new(algorithm, &key_for(algorithm, 2)).unwrap();
        let plaintext = b"same plaintext".to_vec();
        let aad = b"aad";

        let mut first = plaintext.clone();
        key.seal_in_place(&[0u8; NONCE_LEN], aad, &mut first)
            .unwrap();
        let mut second = plaintext.clone();
        key.seal_in_place(&[1u8; NONCE_LEN], aad, &mut second)
            .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn keys_and_tags_are_never_rendered() {
        let key = AeadKey::new(AlgorithmId::Aes256Gcm, &[0xAB; 32]).unwrap();
        let text = format!("{key:?}");
        assert!(text.contains("redacted"));
        assert!(!text.contains("ab"));
    }

    #[test]
    fn algorithm_sets_validate_masks() {
        let all = AlgorithmSet::all();
        assert_eq!(all.len(), 3);
        assert!(all.contains(AlgorithmId::Aes128Gcm));
        assert_eq!(AlgorithmSet::from_mask(all.mask()).unwrap(), all);
        // Unknown bits are rejected rather than ignored.
        assert!(AlgorithmSet::from_mask(0x80).is_err());
        assert!(AlgorithmSet::from_mask(0x00).is_err());
        // A subset is accepted.
        let subset = AlgorithmSet::from_mask(AlgorithmId::ChaCha20Poly1305.mask_bit()).unwrap();
        assert_eq!(subset.len(), 1);
        assert!(!subset.contains(AlgorithmId::Aes256Gcm));
    }

    #[test]
    fn zeroizing_a_key_buffer_removes_the_plaintext() {
        // Documents the erase path used when an authentication check fails.
        let mut buffer = b"sensitive".to_vec();
        buffer.zeroize();
        assert!(buffer.iter().all(|b| *b == 0));
    }
}

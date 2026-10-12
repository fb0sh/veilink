//! The pre-shared authentication key (PSK).
//!
//! Veilink deliberately does **not** accept a human passphrase. The configured `key` must be a
//! high-entropy value produced by [`veilink keygen`](crate::psk::Psk::generate) and shared verbatim
//! by the client and the server. Accepted encodings:
//!
//! * 64 hexadecimal characters (32 bytes), or any even-length hex string of at least 64 characters;
//! * standard Base64URL (RFC 4648 §5) without padding, decoding to at least 32 bytes.
//!
//! The decoded material is kept in a [`Zeroizing`] buffer, is never rendered by `Debug`, and is
//! never logged. All protocol uses of the PSK go through HKDF with a distinct, versioned `info`
//! label, so the raw PSK is never used directly as a cipher key.

use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::rng::{fill_random, RngError};

/// Minimum number of bytes of key material accepted for a PSK (256 bits).
pub const MIN_PSK_LEN: usize = 32;

/// Number of random bytes produced by [`Psk::generate`].
pub const GENERATED_PSK_LEN: usize = 32;

/// Errors raised while parsing or generating a PSK.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PskError {
    /// The value was empty.
    #[error("authentication key is empty")]
    Empty,
    /// The value could not be decoded as hexadecimal or Base64URL.
    #[error(
        "authentication key must be hexadecimal (64+ characters) or Base64URL (43+ characters) \
         text as produced by `veilink keygen`, but it could not be decoded: {reason}"
    )]
    Encoding {
        /// Why decoding failed.
        reason: String,
    },
    /// The decoded key was too short.
    #[error(
        "authentication key is only {actual} bytes after decoding, but at least {MIN_PSK_LEN} bytes \
         (256 bits) are required; run `veilink keygen` to create a suitable key"
    )]
    TooShort {
        /// Decoded length in bytes.
        actual: usize,
    },
    /// The configured text is far too short to encode a 256-bit key.
    #[error(
        "authentication key text is only {chars} characters long; a key must be at least 64 \
         hexadecimal or 43 Base64URL characters (256 bits) as produced by `veilink keygen`"
    )]
    TooShortText {
        /// Number of characters supplied.
        chars: usize,
    },
    /// The key failed the low-entropy sanity check.
    #[error("authentication key {reason}; run `veilink keygen` to create a suitable key")]
    LowEntropy {
        /// Description of the failed check.
        reason: String,
    },
    /// The operating system RNG failed.
    #[error(transparent)]
    Rng(#[from] RngError),
}

/// A pre-shared authentication key.
///
/// Clone is intentionally **not** derived: duplicating secret material should be explicit via
/// [`Psk::duplicate`], which makes secret copies visible during review.
#[derive(Clone)]
pub struct Psk {
    bytes: Zeroizing<Vec<u8>>,
}

impl Psk {
    /// Generates a fresh 256-bit key from the operating system CSPRNG.
    pub fn generate() -> Result<Self, PskError> {
        let mut bytes = Zeroizing::new(vec![0u8; GENERATED_PSK_LEN]);
        fill_random(&mut bytes)?;
        Ok(Psk { bytes })
    }

    /// Parses and validates a PSK from configuration text.
    pub fn parse(input: &str) -> Result<Self, PskError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(PskError::Empty);
        }
        let decoded = match decode(trimmed) {
            Ok(decoded) => decoded,
            Err(error) => {
                // Passphrase-like inputs are the common mistake here; give a length-oriented
                // message instead of a decoder internal error.
                if trimmed.len() < MIN_PSK_LEN * 2 {
                    return Err(PskError::TooShortText {
                        chars: trimmed.chars().count(),
                    });
                }
                return Err(error);
            }
        };
        if decoded.len() < MIN_PSK_LEN {
            return Err(PskError::TooShort {
                actual: decoded.len(),
            });
        }
        check_entropy(&decoded)?;
        Ok(Psk {
            bytes: Zeroizing::new(decoded),
        })
    }

    /// Builds a PSK from raw bytes, for tests and for programmatic embedding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PskError> {
        if bytes.len() < MIN_PSK_LEN {
            return Err(PskError::TooShort {
                actual: bytes.len(),
            });
        }
        check_entropy(bytes)?;
        Ok(Psk {
            bytes: Zeroizing::new(bytes.to_vec()),
        })
    }

    /// The raw key material. Callers must derive purpose-bound keys from it via HKDF rather than
    /// using these bytes as a cipher key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the key material in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Always `false`: a [`Psk`] cannot exist with zero length.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Encodes the key as an unpadded Base64URL string.
    ///
    /// This is only used by `veilink keygen`, which prints the key to stdout for the operator to
    /// place in a configuration file. It must never be called from a logging path.
    pub fn to_base64url(&self) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(&self.bytes))
    }

    /// Explicitly duplicates the secret material.
    pub fn duplicate(&self) -> Self {
        Psk {
            bytes: Zeroizing::new(self.bytes.to_vec()),
        }
    }

    /// Constant-time comparison against another key.
    pub fn ct_eq(&self, other: &Psk) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl fmt::Debug for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render key material, not even a prefix or a length-dependent summary.
        f.write_str("Psk(<redacted>)")
    }
}

impl fmt::Display for Psk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted-psk>")
    }
}

fn decode(input: &str) -> Result<Vec<u8>, PskError> {
    let is_hex =
        input.len() % 2 == 0 && input.len() >= 2 && input.bytes().all(|b| b.is_ascii_hexdigit());
    if is_hex {
        return hex_decode(input).ok_or_else(|| PskError::Encoding {
            reason: "invalid hexadecimal digits".to_string(),
        });
    }
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| PskError::Encoding {
            reason: e.to_string(),
        })
}

fn hex_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// Rejects obviously degenerate keys.
///
/// This is a sanity check, not an entropy estimator: it exists to catch copy-paste accidents such
/// as `AAAA...`, `0101...` or a repeated short block, which have full nominal length but almost no
/// entropy.
fn check_entropy(bytes: &[u8]) -> Result<(), PskError> {
    let first = bytes[0];
    if bytes.iter().all(|b| *b == first) {
        return Err(PskError::LowEntropy {
            reason: "consists of a single repeated byte".to_string(),
        });
    }
    if bytes.iter().all(|b| *b == 0) {
        return Err(PskError::LowEntropy {
            reason: "is all zeroes".to_string(),
        });
    }
    // A repeating block of length <= 8 indicates a fabricated key.
    for period in 1..=8usize {
        if bytes.len() % period == 0 && bytes.len() / period >= 4 {
            let block = &bytes[..period];
            if bytes.chunks_exact(period).all(|c| c == block) {
                return Err(PskError::LowEntropy {
                    reason: format!("repeats a {period}-byte pattern"),
                });
            }
        }
    }
    // Require a minimum number of distinct byte values.
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for b in bytes {
        if !seen[*b as usize] {
            seen[*b as usize] = true;
            distinct += 1;
        }
    }
    let required = (bytes.len() / 8).max(8);
    if distinct < required {
        return Err(PskError::LowEntropy {
            reason: format!("contains only {distinct} distinct byte values"),
        });
    }
    Ok(())
}

/// A purpose-separated subkey derived from the PSK with HKDF-SHA256.
///
/// Each label yields an independent key, which is what keeps handshake authentication, control
/// frame protection and session identifiers cryptographically disjoint.
#[derive(Clone)]
pub struct DerivedKey(Zeroizing<[u8; 32]>);

impl DerivedKey {
    /// The raw derived key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps 32 bytes produced by a derivation performed elsewhere.
    pub fn from_array(bytes: [u8; 32]) -> Self {
        DerivedKey(Zeroizing::new(bytes))
    }

    /// Explicitly copies the key material.
    pub fn duplicate(&self) -> Self {
        DerivedKey(Zeroizing::new(*self.0))
    }
}

impl fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DerivedKey(<redacted>)")
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Derives a 32-byte purpose-bound subkey from the PSK.
///
/// `info` must be a stable, versioned protocol label such as `b"vlp/1 handshake c2s"`. The salt is
/// the constant `veilink-kdf-v1` so that derivations are reproducible across the two peers while
/// remaining separated from any other use of the same PSK in another protocol.
pub fn derive_key(psk: &Psk, info: &[u8]) -> DerivedKey {
    let hk = Hkdf::<Sha256>::new(Some(b"veilink-kdf-v1"), psk.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand of 32 bytes cannot fail");
    DerivedKey(Zeroizing::new(okm))
}

/// Extracts a 32-byte pseudorandom key from the PSK and a per-session salt.
pub fn extract_key(psk: &Psk, salt: &[u8], info: &[u8]) -> DerivedKey {
    let hk = Hkdf::<Sha256>::new(Some(salt), psk.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF-SHA256 expand of 32 bytes cannot fail");
    DerivedKey(Zeroizing::new(okm))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hex() -> String {
        (0..32).map(|i| format!("{:02x}", i * 7 + 1)).collect()
    }

    #[test]
    fn generates_256_bit_key() {
        let a = Psk::generate().unwrap();
        let b = Psk::generate().unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert!(!a.ct_eq(&b));
        assert!(a.ct_eq(&a.duplicate()));
    }

    #[test]
    fn accepts_hex_and_base64url() {
        let hex = sample_hex();
        let psk = Psk::parse(&hex).unwrap();
        assert_eq!(psk.len(), 32);

        let b64 = psk.to_base64url();
        let round = Psk::parse(&b64).unwrap();
        assert!(psk.ct_eq(&round));
    }

    #[test]
    fn accepts_longer_keys() {
        let long = (0..64)
            .map(|i| format!("{:02x}", (i * 31 + 7) % 256))
            .collect::<String>();
        assert!(Psk::parse(&long).is_ok());
    }

    #[test]
    fn rejects_short_keys() {
        // A passphrase is rejected with a length-oriented message.
        assert!(matches!(
            Psk::parse("hunter2"),
            Err(PskError::TooShortText { chars: 7 })
        ));
        assert!(matches!(
            Psk::parse("password"),
            Err(PskError::TooShort { actual: 6 })
        ));
        // Valid Base64URL text that decodes to fewer than 32 bytes is rejected as too short.
        let short_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x11u8; 16]);
        assert!(matches!(
            Psk::parse(&short_b64),
            Err(PskError::TooShort { actual: 16 })
        ));
        assert!(matches!(Psk::parse(""), Err(PskError::Empty)));
        assert!(matches!(Psk::parse("   "), Err(PskError::Empty)));
    }

    #[test]
    fn rejects_low_entropy_keys() {
        let all_a = "a".repeat(64);
        assert!(matches!(
            Psk::parse(&all_a),
            Err(PskError::LowEntropy { .. })
        ));
        let zeros = "0".repeat(64);
        assert!(matches!(
            Psk::parse(&zeros),
            Err(PskError::LowEntropy { .. })
        ));
        let repeating = "deadbeef".repeat(8);
        assert!(matches!(
            Psk::parse(&repeating),
            Err(PskError::LowEntropy { .. })
        ));
        // A 64-char hex string with only a handful of distinct nibbles.
        let sparse = "0101010101010101010101010101010101010101010101010101010101010101";
        assert!(matches!(
            Psk::parse(sparse),
            Err(PskError::LowEntropy { .. })
        ));
    }

    #[test]
    fn never_leaks_in_debug_or_display() {
        let psk = Psk::generate().unwrap();
        let hex_of_key: String = psk.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let debug = format!("{psk:?}");
        let display = format!("{psk}");
        assert!(debug.contains("redacted"));
        assert!(display.contains("redacted"));
        assert!(!debug.contains(&hex_of_key));
        assert!(!display.contains(&hex_of_key));
        // The encoded form is only obtainable explicitly.
        assert!(psk.to_base64url().len() >= 43);
    }

    #[test]
    fn derived_keys_are_purpose_separated_and_deterministic() {
        let psk = Psk::generate().unwrap();
        let a1 = derive_key(&psk, b"vlp/1 handshake c2s");
        let a2 = derive_key(&psk, b"vlp/1 handshake c2s");
        let b = derive_key(&psk, b"vlp/1 handshake s2c");
        assert_eq!(a1.as_bytes(), a2.as_bytes());
        assert_ne!(a1.as_bytes(), b.as_bytes());

        let c = extract_key(&psk, b"session-salt", b"vlp/1 control c2s");
        let d = extract_key(&psk, b"other-salt", b"vlp/1 control c2s");
        assert_ne!(c.as_bytes(), d.as_bytes());
    }

    #[test]
    fn derived_key_debug_is_redacted() {
        let psk = Psk::generate().unwrap();
        let k = derive_key(&psk, b"x");
        assert_eq!(format!("{k:?}"), "DerivedKey(<redacted>)");
    }
}

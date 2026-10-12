//! Randomness acquisition.
//!
//! Every secret in Veilink comes from the operating system CSPRNG. There is deliberately no
//! fallback: if the system entropy source fails, the operation fails loudly instead of silently
//! degrading to a weaker source. See [`RngError`].

use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

/// Failure to obtain randomness from the operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("operating system random number generator failed")]
pub struct RngError;

/// Fills `dest` with cryptographically secure random bytes.
///
/// Returns [`RngError`] if the OS entropy source is unavailable. Callers must propagate this error
/// and abort the operation; never substitute predictable material.
pub fn fill_random(dest: &mut [u8]) -> Result<(), RngError> {
    // `try_fill_bytes` surfaces the OS error instead of panicking, which lets protocol code fail
    // closed during a handshake.
    OsRng.try_fill_bytes(dest).map_err(|_| RngError)
}

/// Returns `N` cryptographically secure random bytes.
pub fn random_array<const N: usize>() -> Result<[u8; N], RngError> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

/// Returns a random `u64`.
pub fn random_u64() -> Result<u64, RngError> {
    Ok(u64::from_be_bytes(random_array::<8>()?))
}

/// Returns a random `u32`.
pub fn random_u32() -> Result<u32, RngError> {
    Ok(u32::from_be_bytes(random_array::<4>()?))
}

/// Returns a uniformly distributed value in `[0, bound)`.
///
/// `bound` must be non-zero. The implementation rejects biased samples (Lemire's method) rather
/// than accepting the modulo bias of `next_u64() % bound`.
pub fn random_below(bound: u64) -> Result<u64, RngError> {
    if bound == 0 {
        return Err(RngError);
    }
    if bound == 1 {
        return Ok(0);
    }
    // Rejection sampling keeps the distribution uniform for any bound.
    let zone = u64::MAX - (u64::MAX % bound) - 1;
    loop {
        let v = random_u64()?;
        if v <= zone {
            return Ok(v % bound);
        }
    }
}

/// Returns a random `u64` strictly greater than zero, suitable for identifiers.
pub fn random_nonzero_u64() -> Result<u64, RngError> {
    loop {
        let v = random_u64()?;
        if v != 0 {
            return Ok(v);
        }
    }
}

/// A random byte buffer that is wiped on drop.
///
/// Used for padding payloads and cover traffic, which are not secret but are derived from the same
/// generator as protocol secrets.
pub struct RandomBytes(Vec<u8>);

impl RandomBytes {
    /// Allocates `len` random bytes.
    pub fn new(len: usize) -> Result<Self, RngError> {
        let mut buf = vec![0u8; len];
        fill_random(&mut buf)?;
        Ok(RandomBytes(buf))
    }
}

impl AsRef<[u8]> for RandomBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for RandomBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_arrays_differ() {
        let a = random_array::<32>().unwrap();
        let b = random_array::<32>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn nonce_uniqueness_smoke() {
        // 4096 random 12-byte nonces must not collide; this catches an accidentally constant source.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..4096 {
            assert!(seen.insert(random_array::<12>().unwrap()));
        }
    }

    #[test]
    fn random_below_is_bounded() {
        for bound in [1u64, 2, 3, 7, 512, 1 << 33] {
            for _ in 0..256 {
                assert!(random_below(bound).unwrap() < bound);
            }
        }
        assert!(random_below(0).is_err());
    }

    #[test]
    fn nonzero_is_never_zero() {
        for _ in 0..1024 {
            assert_ne!(random_nonzero_u64().unwrap(), 0);
        }
    }

    #[test]
    fn random_bytes_len() {
        assert_eq!(RandomBytes::new(17).unwrap().as_ref().len(), 17);
    }
}

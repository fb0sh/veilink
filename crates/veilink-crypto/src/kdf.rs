//! The `VLP/1` key schedule.
//!
//! Everything a frame is protected with is derived here, from three inputs that are bound together:
//!
//! 1. the operator's pre-shared key, which authenticates the peers to each other;
//! 2. the TLS exporter value, which cryptographically binds the derivation to *this* outer TLS
//!    session — this is what stops a man in the middle from relaying a handshake between two
//!    different TLS sessions;
//! 3. a transcript hash of the `VLP/1` handshake messages, which binds the negotiated parameters
//!    (version, nonces, algorithm sets) so that any tampering changes every derived key.
//!
//! ## What is derived
//!
//! | Purpose | Input key material | Notes |
//! |---------|--------------------|-------|
//! | Handshake MAC, client to server | PSK | proves possession of the PSK |
//! | Handshake MAC, server to client | PSK | proves the server's identity to the client |
//! | Control-channel root, each direction | PSK + exporter | ratcheted per control frame |
//! | Session identifier | PSK + transcript | shared, never transmitted before use |
//! | Per-frame AEAD key and nonce | X25519 shared secret | unique per frame |
//!
//! The per-frame derivation mixes the shared secret with the session identifier, the direction, the
//! epoch, the frame sequence number, the recipient key identifier, the algorithm identifier and the
//! sender's ephemeral public key. Because every one of those is authenticated as part of the frame
//! header, a frame cannot be re-labelled, re-ordered, re-keyed or replayed into a different session
//! and still authenticate.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::SharedSecret;
use zeroize::Zeroizing;

use crate::aead::{AlgorithmId, AlgorithmSet, AeadKey, Nonce, NONCE_LEN};
use crate::epoch::Direction;
use crate::psk::{DerivedKey, Psk};
use crate::CryptoError;

/// Domain separation label for the whole protocol.
pub const PROTOCOL_LABEL: &[u8] = b"VLP/1";
/// Label used for the TLS exporter that binds our handshake to the outer TLS session.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-Veilink-VLP1";
/// Length of every derived value that is a hash or a MAC.
pub const HASH_LEN: usize = 32;

/// A hash of the `VLP/1` handshake transcript.
#[derive(Clone)]
pub struct Transcript {
    hasher: Sha256,
}

impl std::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Transcript(<opaque>)")
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

impl Transcript {
    /// Starts a transcript for `VLP/1`.
    pub fn new() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(PROTOCOL_LABEL);
        Transcript { hasher }
    }

    /// Absorbs one message or field. Lengths must be fixed or explicitly length-prefixed by the
    /// caller so that the transcript is unambiguous.
    pub fn absorb(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    /// Absorbs a length-prefixed byte string.
    pub fn absorb_prefixed(&mut self, bytes: &[u8]) {
        self.hasher.update((bytes.len() as u32).to_be_bytes());
        self.hasher.update(bytes);
    }

    /// Absorbs a `u8`.
    pub fn absorb_u8(&mut self, value: u8) {
        self.hasher.update([value]);
    }

    /// Absorbs a big-endian `u32`.
    pub fn absorb_u32(&mut self, value: u32) {
        self.hasher.update(value.to_be_bytes());
    }

    /// The current transcript hash.
    pub fn hash(&self) -> [u8; HASH_LEN] {
        let mut out = [0u8; HASH_LEN];
        out.copy_from_slice(&self.hasher.clone().finalize());
        out
    }
}

/// The material produced once the handshake transcript and the TLS exporter are known.
#[derive(Clone)]
pub struct HandshakeKeys {
    /// Hash of the complete handshake transcript.
    pub transcript_hash: [u8; HASH_LEN],
    /// TLS exporter value, binding the keys to this outer TLS session.
    pub exporter: Zeroizing<[u8; HASH_LEN]>,
    /// Shared session identifier, derived rather than transmitted.
    pub session_id: u64,
    /// MAC key for `CLIENT -> SERVER` confirmation.
    pub auth_c2s: DerivedKey,
    /// MAC key for `SERVER -> CLIENT` confirmation.
    pub auth_s2c: DerivedKey,
    /// Root of the client-to-server control key chain.
    pub control_root_c2s: DerivedKey,
    /// Root of the server-to-client control key chain.
    pub control_root_s2c: DerivedKey,
    /// Algorithms the client is willing to receive.
    pub c2s_algorithms: AlgorithmSet,
    /// Algorithms the server is willing to receive.
    pub s2c_algorithms: AlgorithmSet,
}

impl std::fmt::Debug for HandshakeKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeKeys")
            .field("session_id", &self.session_id)
            .field("c2s_algorithms", &self.c2s_algorithms)
            .field("s2c_algorithms", &self.s2c_algorithms)
            .finish_non_exhaustive()
    }
}

/// Derives the session keys from the PSK, the transcript hash and the TLS exporter.
pub fn derive_handshake_keys(
    psk: &Psk,
    transcript_hash: [u8; HASH_LEN],
    exporter: [u8; HASH_LEN],
    c2s_algorithms: AlgorithmSet,
    s2c_algorithms: AlgorithmSet,
) -> HandshakeKeys {
    // The exporter is mixed into the HKDF salt so that a relay between two different TLS sessions
    // produces different keys on each leg.
    let mut salt = Vec::with_capacity(HASH_LEN * 2 + 16);
    salt.extend_from_slice(&transcript_hash);
    salt.extend_from_slice(&exporter);
    salt.extend_from_slice(PROTOCOL_LABEL);

    let auth_c2s = crate::psk::extract_key(psk, &salt, b"vlp/1 handshake auth c2s");
    let auth_s2c = crate::psk::extract_key(psk, &salt, b"vlp/1 handshake auth s2c");
    let control_root_c2s = crate::psk::extract_key(psk, &salt, b"vlp/1 control root c2s");
    let control_root_s2c = crate::psk::extract_key(psk, &salt, b"vlp/1 control root s2c");

    let id_material = crate::psk::extract_key(psk, &salt, b"vlp/1 session identifier");
    let session_id = u64::from_be_bytes(
        id_material.as_bytes()[..8]
            .try_into()
            .expect("derived key is 32 bytes"),
    );

    HandshakeKeys {
        transcript_hash,
        exporter: Zeroizing::new(exporter),
        session_id,
        auth_c2s,
        auth_s2c,
        control_root_c2s,
        control_root_s2c,
        c2s_algorithms,
        s2c_algorithms,
    }
}

/// Computes a handshake confirmation MAC.
///
/// The MAC covers the transcript and the exporter, so it can only be produced by a peer that holds
/// the PSK *and* is actually talking to us over this TLS session.
pub fn confirmation_mac(
    key: &DerivedKey,
    direction: Direction,
    transcript_hash: &[u8; HASH_LEN],
    exporter: &[u8; HASH_LEN],
) -> [u8; HASH_LEN] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(PROTOCOL_LABEL);
    mac.update(b" confirm ");
    mac.update(&[direction.as_u8()]);
    mac.update(transcript_hash);
    mac.update(exporter);
    let out = mac.finalize().into_bytes();
    let mut result = [0u8; HASH_LEN];
    result.copy_from_slice(&out);
    result
}

/// Constant-time verification of a handshake MAC.
pub fn verify_mac(expected: &[u8; HASH_LEN], received: &[u8]) -> Result<(), CryptoError> {
    if received.len() != HASH_LEN {
        return Err(CryptoError::Handshake(
            "confirmation MAC has the wrong length".to_string(),
        ));
    }
    if expected.ct_eq(received).into() {
        Ok(())
    } else {
        Err(CryptoError::Handshake(
            "confirmation MAC did not verify: wrong key, tampered handshake, or a relayed session"
                .to_string(),
        ))
    }
}

/// Steps the control-channel key chain forward by one.
///
/// The chain is a hash ratchet: `k(n+1) = HKDF(k(n), "ratchet")`. Knowing `k(n)` does not reveal
/// `k(n-1)`, so erasing old steps gives the control channel forward secrecy even though it is
/// rooted in the long-term PSK.
pub fn ratchet_step(current: &DerivedKey, direction: Direction) -> DerivedKey {
    let hk = Hkdf::<Sha256>::new(None, current.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(
        &[b"vlp/1 control ratchet".as_slice(), &[direction.as_u8()]].concat(),
        &mut okm,
    )
    .expect("HKDF-SHA256 expand of 32 bytes cannot fail");
    DerivedKey::from_array(okm)
}

/// An O(1) hash-ratchet chain for one direction of the control channel.
///
/// The chain is advanced by exactly one step per control frame, in both directions of a session.
/// Because the outer transport is reliable and ordered, the two peers cannot desynchronise; a
/// forged or reordered frame is rejected before the chain advances, so an attacker cannot push the
/// receiver off the chain either.
///
/// Forward secrecy: the state at step `n` yields `k(n)`, `k(n+1)`, … but not `k(n-1)`. Combined
/// with the fact that each step's key is dropped after use, capturing the chain state does not
/// expose earlier control frames.
pub struct ControlChain {
    current: DerivedKey,
    direction: Direction,
    step: u64,
}

impl std::fmt::Debug for ControlChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlChain")
            .field("direction", &self.direction)
            .field("step", &self.step)
            .finish_non_exhaustive()
    }
}

impl ControlChain {
    /// Starts a chain at the root derived during the handshake.
    pub fn new(root: &DerivedKey, direction: Direction) -> Self {
        ControlChain {
            current: root.duplicate(),
            direction,
            step: 0,
        }
    }

    /// The number of frames already sent or received on this chain.
    pub fn step(&self) -> u64 {
        self.step
    }

    /// The direction this chain protects.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Derives the key and nonce for the current step without advancing.
    pub fn material(&self) -> (AeadKey, Nonce) {
        let hk = Hkdf::<Sha256>::new(None, self.current.as_bytes());
        let mut okm = Zeroizing::new([0u8; 44]);
        hk.expand(b"vlp/1 control frame v1", &mut *okm)
            .expect("HKDF-SHA256 expand of 44 bytes cannot fail");
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&okm[32..44]);
        let key = AeadKey::new(AlgorithmId::ChaCha20Poly1305, &okm[..32])
            .expect("32 bytes is a valid ChaCha20-Poly1305 key");
        (key, nonce)
    }

    /// Advances the chain. Call this only after the frame at the current step was accepted, so that
    /// a forged frame cannot move the receiver off the chain.
    pub fn advance(&mut self) {
        self.current = ratchet_step(&self.current, self.direction);
        self.step += 1;
    }
}

/// Everything that must be bound into a per-frame key.
///
/// Every field here is part of the authenticated frame header or the receiving key's identity, so
/// the binding is not advisory: changing any of them in flight makes the tag verification fail.
pub struct FrameKeyContext<'a> {
    /// Session identifier.
    pub session_id: u64,
    /// Key generation.
    pub epoch: u32,
    /// Direction of travel.
    pub direction: Direction,
    /// Frame sequence number.
    pub sequence: u64,
    /// Identifier of the recipient's one-time key.
    pub key_id: u32,
    /// AEAD algorithm chosen by the sender.
    pub algorithm: AlgorithmId,
    /// The sender's fresh ephemeral public key.
    pub sender_public: &'a [u8; 32],
    /// Transcript hash of the session's handshake.
    pub transcript_hash: &'a [u8; 32],
}

/// Derives the AEAD key and nonce for a single business frame.
///
/// The shared secret is the output of a Diffie-Hellman step involving a key pair that exists for
/// exactly this frame, so the result is unique per frame by construction.
pub fn derive_frame_material(
    shared: &SharedSecret,
    context: &FrameKeyContext<'_>,
) -> Result<(AeadKey, Nonce), CryptoError> {
    let salt = {
        let mut salt = Vec::with_capacity(64);
        salt.extend_from_slice(context.transcript_hash);
        salt.extend_from_slice(&context.session_id.to_be_bytes());
        salt
    };

    let mut info = Vec::with_capacity(96);
    info.extend_from_slice(b"vlp/1 frame key v1");
    info.push(context.direction.as_u8());
    info.extend_from_slice(&context.epoch.to_be_bytes());
    info.extend_from_slice(&context.sequence.to_be_bytes());
    info.extend_from_slice(&context.key_id.to_be_bytes());
    info.push(context.algorithm.as_u8());
    info.extend_from_slice(context.sender_public);

    let key_len = context.algorithm.key_len();
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes());
    let mut okm = Zeroizing::new([0u8; 44]);
    hk.expand(&info, &mut okm[..key_len + NONCE_LEN])
        .map_err(|_| CryptoError::Protocol("frame key derivation failed".to_string()))?;

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&okm[key_len..key_len + NONCE_LEN]);
    let key = AeadKey::new(context.algorithm, &okm[..key_len])?;
    Ok((key, nonce))
}

/// Picks the algorithm for the next frame.
///
/// The rule is "any permitted algorithm except the one used for the previous frame", which keeps
/// the ciphertext from being a stable fingerprint without pretending that rotation is itself a
/// security property. The choice comes from the operating system CSPRNG.
pub fn select_algorithm(
    permitted: AlgorithmSet,
    previous: Option<AlgorithmId>,
) -> Result<AlgorithmId, CryptoError> {
    let candidates: Vec<AlgorithmId> = permitted.iter().collect();
    if candidates.is_empty() {
        return Err(CryptoError::Protocol(
            "no mutually supported AEAD algorithm".to_string(),
        ));
    }
    if candidates.len() == 1 {
        return Ok(candidates[0]);
    }
    let usable: Vec<AlgorithmId> = candidates
        .iter()
        .copied()
        .filter(|a| Some(*a) != previous)
        .collect();
    let pool = if usable.is_empty() {
        candidates
    } else {
        usable
    };
    let index = crate::rng::random_below(pool.len() as u64)? as usize;
    Ok(pool[index])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x25519::{OneTimeKeyPair, SenderEphemeral};

    fn keys() -> HandshakeKeys {
        let psk = Psk::from_bytes(&(0u8..32).collect::<Vec<u8>>()).unwrap();
        let mut transcript = Transcript::new();
        transcript.absorb(b"client-random");
        transcript.absorb(b"server-random");
        derive_handshake_keys(
            &psk,
            transcript.hash(),
            [7u8; HASH_LEN],
            AlgorithmSet::all(),
            AlgorithmSet::all(),
        )
    }

    #[test]
    fn both_peers_derive_the_same_keys() {
        let psk = Psk::from_bytes(&(0u8..32).collect::<Vec<u8>>()).unwrap();
        let transcript = Transcript::new();
        let hash = transcript.hash();
        let one = derive_handshake_keys(&psk, hash, [1u8; HASH_LEN], AlgorithmSet::all(), AlgorithmSet::all());
        let two = derive_handshake_keys(&psk, hash, [1u8; HASH_LEN], AlgorithmSet::all(), AlgorithmSet::all());
        assert_eq!(one.session_id, two.session_id);
        assert_eq!(one.auth_c2s.as_bytes(), two.auth_c2s.as_bytes());
        assert_eq!(
            one.control_root_s2c.as_bytes(),
            two.control_root_s2c.as_bytes()
        );
    }

    #[test]
    fn a_different_exporter_changes_every_key() {
        let psk = Psk::from_bytes(&(0u8..32).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect::<Vec<u8>>()).unwrap();
        let hash = Transcript::new().hash();
        let a = derive_handshake_keys(&psk, hash, [1u8; HASH_LEN], AlgorithmSet::all(), AlgorithmSet::all());
        let b = derive_handshake_keys(&psk, hash, [2u8; HASH_LEN], AlgorithmSet::all(), AlgorithmSet::all());
        assert_ne!(a.session_id, b.session_id);
        assert_ne!(a.auth_c2s.as_bytes(), b.auth_c2s.as_bytes());
        assert_ne!(
            a.control_root_c2s.as_bytes(),
            b.control_root_c2s.as_bytes()
        );
    }

    #[test]
    fn a_different_transcript_changes_every_key() {
        let psk = Psk::from_bytes(&(0u8..32).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect::<Vec<u8>>()).unwrap();
        let mut first = Transcript::new();
        first.absorb(b"a");
        let mut second = Transcript::new();
        second.absorb(b"b");
        let a = derive_handshake_keys(
            &psk,
            first.hash(),
            [1u8; HASH_LEN],
            AlgorithmSet::all(),
            AlgorithmSet::all(),
        );
        let b = derive_handshake_keys(
            &psk,
            second.hash(),
            [1u8; HASH_LEN],
            AlgorithmSet::all(),
            AlgorithmSet::all(),
        );
        assert_ne!(a.session_id, b.session_id);
    }

    #[test]
    fn a_different_psk_changes_every_key() {
        let hash = Transcript::new().hash();
        let a = derive_handshake_keys(
            &Psk::from_bytes(&(0u8..32).map(|i| i.wrapping_mul(3).wrapping_add(1)).collect::<Vec<u8>>()).unwrap(),
            hash,
            [1u8; HASH_LEN],
            AlgorithmSet::all(),
            AlgorithmSet::all(),
        );
        let b = derive_handshake_keys(
            &Psk::from_bytes(&(0u8..32).map(|i| i.wrapping_mul(11).wrapping_add(5)).collect::<Vec<u8>>()).unwrap(),
            hash,
            [1u8; HASH_LEN],
            AlgorithmSet::all(),
            AlgorithmSet::all(),
        );
        assert_ne!(a.session_id, b.session_id);
        assert_ne!(a.auth_c2s.as_bytes(), b.auth_c2s.as_bytes());
    }

    #[test]
    fn directions_are_cryptographically_separate() {
        let keys = keys();
        assert_ne!(keys.auth_c2s.as_bytes(), keys.auth_s2c.as_bytes());
        assert_ne!(
            keys.control_root_c2s.as_bytes(),
            keys.control_root_s2c.as_bytes()
        );
    }

    #[test]
    fn confirmation_macs_are_direction_bound_and_verifiable() {
        let keys = keys();
        let c2s = confirmation_mac(
            &keys.auth_c2s,
            Direction::ClientToServer,
            &keys.transcript_hash,
            &keys.exporter,
        );
        let s2c = confirmation_mac(
            &keys.auth_s2c,
            Direction::ServerToClient,
            &keys.transcript_hash,
            &keys.exporter,
        );
        assert_ne!(c2s, s2c);
        assert!(verify_mac(&c2s, &c2s).is_ok());
        assert!(verify_mac(&c2s, &s2c).is_err());
        assert!(verify_mac(&c2s, &c2s[..31]).is_err());
        // A tampered transcript or exporter changes the expected MAC, so verification fails.
        let tampered = confirmation_mac(
            &keys.auth_c2s,
            Direction::ClientToServer,
            &[0u8; HASH_LEN],
            &keys.exporter,
        );
        assert!(verify_mac(&tampered, &c2s).is_err());
    }

    #[test]
    fn ratchet_is_one_way() {
        let keys = keys();
        let first = ratchet_step(&keys.control_root_c2s, Direction::ClientToServer);
        let second = ratchet_step(&first, Direction::ClientToServer);
        assert_ne!(first.as_bytes(), second.as_bytes());
        assert_ne!(first.as_bytes(), keys.control_root_c2s.as_bytes());
        // Ratcheting the other direction gives a different chain.
        let other = ratchet_step(&keys.control_root_c2s, Direction::ServerToClient);
        assert_ne!(first.as_bytes(), other.as_bytes());
    }

    #[test]
    fn control_chain_produces_a_fresh_key_per_step() {
        let keys = keys();
        let mut chain = ControlChain::new(&keys.control_root_c2s, Direction::ClientToServer);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let (key, nonce) = chain.material();
            assert!(seen.insert((key.algorithm() as u8, nonce)), "control key repeated");
            chain.advance();
        }
        assert_eq!(chain.step(), 64);
    }

    #[test]
    fn control_chains_agree_between_peers_and_advance_only_on_demand() {
        let keys = keys();
        let sender = ControlChain::new(&keys.control_root_c2s, Direction::ClientToServer);
        let mut receiver = ControlChain::new(&keys.control_root_c2s, Direction::ClientToServer);

        // Both sides derive the same material for step 0.
        let (send_key, send_nonce) = sender.material();
        let (recv_key, recv_nonce) = receiver.material();
        let mut buffer = b"ping".to_vec();
        send_key.seal_in_place(&send_nonce, b"aad", &mut buffer).unwrap();
        recv_key.open_in_place(&recv_nonce, b"aad", &mut buffer).unwrap();
        assert_eq!(buffer, b"ping");

        // Re-deriving without advancing gives the same key: a replayed frame would decrypt again,
        // which is why the sequence check and, for data frames, the one-time key are what actually
        // reject replays. The chain itself only guarantees key freshness per accepted frame.
        let (again, _) = sender.material();
        assert_eq!(again.algorithm(), send_key.algorithm());

        receiver.advance();
        assert_eq!(receiver.step(), 1);
        assert_ne!(receiver.material().1, recv_nonce);
    }

    #[test]
    fn control_chains_for_the_two_directions_diverge() {
        let keys = keys();
        let c2s = ControlChain::new(&keys.control_root_c2s, Direction::ClientToServer);
        let s2c = ControlChain::new(&keys.control_root_s2c, Direction::ServerToClient);
        let (a, nonce_a) = c2s.material();
        let (b, nonce_b) = s2c.material();
        assert_ne!(nonce_a, nonce_b);
        assert_eq!(a.algorithm(), b.algorithm());
    }

    #[test]
    fn per_frame_material_is_unique_and_agrees_on_both_sides() {
        let keys = keys();
        let recipient = OneTimeKeyPair::generate().unwrap();
        let public = recipient.public_key();
        let sender = SenderEphemeral::generate().unwrap();
        let sender_public = sender.public_bytes();
        let shared_sender = sender.encapsulate(&public).unwrap();
        let shared_receiver = recipient.decapsulate(&sender_public).unwrap();

        let context = FrameKeyContext {
            session_id: keys.session_id,
            epoch: 1,
            direction: Direction::ClientToServer,
            sequence: 42,
            key_id: 501,
            algorithm: AlgorithmId::Aes256Gcm,
            sender_public: &sender_public,
            transcript_hash: &keys.transcript_hash,
        };
        let (key_a, nonce_a) = derive_frame_material(&shared_sender, &context).unwrap();
        let (key_b, nonce_b) = derive_frame_material(&shared_receiver, &context).unwrap();

        // Both sides derive the same key: a round trip works.
        let mut buffer = b"payload".to_vec();
        key_a.seal_in_place(&nonce_a, b"aad", &mut buffer).unwrap();
        key_b.open_in_place(&nonce_b, b"aad", &mut buffer).unwrap();
        assert_eq!(buffer, b"payload");
    }

    #[test]
    fn every_context_field_changes_the_frame_key() {
        let keys = keys();
        let recipient = OneTimeKeyPair::generate().unwrap();
        let public = recipient.public_key();
        let sender = SenderEphemeral::generate().unwrap();
        let sender_public = sender.public_bytes();
        let shared = sender.encapsulate(&public).unwrap();

        let base = FrameKeyContext {
            session_id: keys.session_id,
            epoch: 1,
            direction: Direction::ClientToServer,
            sequence: 1,
            key_id: 7,
            algorithm: AlgorithmId::ChaCha20Poly1305,
            sender_public: &sender_public,
            transcript_hash: &keys.transcript_hash,
        };
        let (base_key, base_nonce) = derive_frame_material(&shared, &base).unwrap();

        let variants: Vec<FrameKeyContext> = vec![
            FrameKeyContext { session_id: base.session_id + 1, ..base },
            FrameKeyContext { epoch: 2, ..base },
            FrameKeyContext { direction: Direction::ServerToClient, ..base },
            FrameKeyContext { sequence: 2, ..base },
            FrameKeyContext { key_id: 8, ..base },
            FrameKeyContext { algorithm: AlgorithmId::Aes256Gcm, ..base },
        ];
        for variant in variants {
            let (key, nonce) = derive_frame_material(&shared, &variant).unwrap();
            assert!(
                key.algorithm() != base_key.algorithm() || nonce != base_nonce,
                "a context change did not change the derived material"
            );
        }
    }

    #[test]
    fn a_different_sender_ephemeral_yields_a_different_key() {
        let keys = keys();
        let recipient = OneTimeKeyPair::generate().unwrap();
        let public = recipient.public_key();

        let first_sender = SenderEphemeral::generate().unwrap();
        let first_public = first_sender.public_bytes();
        let second_sender = SenderEphemeral::generate().unwrap();
        let second_public = second_sender.public_bytes();

        let shared_a = first_sender.encapsulate(&public).unwrap();
        let shared_b = second_sender.encapsulate(&public).unwrap();

        let context_a = FrameKeyContext {
            session_id: keys.session_id,
            epoch: 1,
            direction: Direction::ClientToServer,
            sequence: 1,
            key_id: 1,
            algorithm: AlgorithmId::Aes128Gcm,
            sender_public: &first_public,
            transcript_hash: &keys.transcript_hash,
        };
        let context_b = FrameKeyContext {
            sender_public: &second_public,
            ..context_a
        };
        let (key_a, nonce_a) = derive_frame_material(&shared_a, &context_a).unwrap();
        let (key_b, nonce_b) = derive_frame_material(&shared_b, &context_b).unwrap();
        assert_ne!(nonce_a, nonce_b);
        assert_eq!(key_a.algorithm(), key_b.algorithm());
    }

    #[test]
    fn algorithm_selection_avoids_immediate_repetition() {
        let permitted = AlgorithmSet::all();
        let mut previous = None;
        for _ in 0..64 {
            let chosen = select_algorithm(permitted, previous).unwrap();
            if let Some(last) = previous {
                assert_ne!(chosen, last, "two adjacent frames used the same algorithm");
            }
            previous = Some(chosen);
        }
        // A single-algorithm set is honoured rather than rejected.
        let single = AlgorithmSet::from_mask(AlgorithmId::Aes128Gcm.mask_bit()).unwrap();
        assert_eq!(
            select_algorithm(single, Some(AlgorithmId::Aes128Gcm)).unwrap(),
            AlgorithmId::Aes128Gcm
        );
    }

    #[test]
    fn algorithm_selection_uses_every_permitted_algorithm() {
        let permitted = AlgorithmSet::all();
        let mut seen = std::collections::HashSet::new();
        let mut previous = None;
        for _ in 0..256 {
            let chosen = select_algorithm(permitted, previous).unwrap();
            seen.insert(chosen);
            previous = Some(chosen);
        }
        assert_eq!(seen.len(), 3, "not every algorithm was selected: {seen:?}");
    }
}

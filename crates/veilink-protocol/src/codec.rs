//! The `VLP/1` session codec: sealing and opening frames.
//!
//! This is where the frame layer meets the cryptography. It owns:
//!
//! * the outbound frame counter and the control-channel key chains;
//! * the local one-time key pool and the peer's published keys;
//! * the padding policy applied inside the encrypted payload.
//!
//! ## Padding
//!
//! Padding happens *inside* the AEAD plaintext, so it is authenticated and invisible on the wire.
//! The plaintext layout is:
//!
//! ```text
//! u16 real length | message bytes | zero padding
//! ```
//!
//! The total plaintext length is rounded up to the next bucket, which makes the ciphertext length
//! a function of the bucket rather than of the payload. Bucket choice is a privacy/bandwidth
//! trade-off, not a security control, and the buckets here are the initial defaults from the
//! design: 512, 1024, 2048, 4096 and 8192 bytes, with a capped tail beyond that.
//!
//! A receiver never trusts the length prefix: it is validated against the actual buffer before the
//! message is decoded, and a mismatch is a protocol error rather than a slice panic.

use std::sync::Arc;

use subtle::ConstantTimeEq;
use veilink_crypto::{
    derive_frame_material, select_algorithm, AlgorithmId, AlgorithmSet, ControlChain, CryptoError,
    Direction, FrameKeyContext, HandshakeKeys, KeyPool, RecipientPublicKey, RecvSequence,
    SendSequence, SenderEphemeral, SequenceMode, TAG_LEN,
};

use crate::frame::{FrameHeader, MAX_CIPHERTEXT, MAX_PAYLOAD};
use crate::message::{Message, MessageError};

/// The epoch used by frames protected with one-time keys.
pub const DATA_EPOCH: u32 = 1;

/// Length of the plaintext length prefix.
const LENGTH_PREFIX: usize = 2;

/// Framing overhead of a `STREAM_DATA` message.
pub const STREAM_DATA_OVERHEAD: usize = 1 + 4 + 4;

/// Errors raised by the session codec.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// The cryptographic layer rejected the frame.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The message payload was malformed.
    #[error(transparent)]
    Message(#[from] MessageError),
    /// The frame did not belong to this session.
    #[error("frame belongs to session {got:#x}, this session is {expected:#x}")]
    WrongSession {
        /// Session identifier in the frame.
        got: u64,
        /// This session's identifier.
        expected: u64,
    },
    /// The frame travelled in the wrong direction.
    #[error("frame direction {got} is not the peer direction {expected}")]
    WrongDirection {
        /// Direction in the frame.
        got: u8,
        /// Direction expected.
        expected: u8,
    },
    /// The frame used an algorithm the receiver never advertised.
    #[error("frame used algorithm {0} which was not offered for this direction")]
    AlgorithmNotOffered(u8),
    /// The frame used an epoch this codec does not implement.
    #[error("frame used unsupported epoch {0}")]
    UnsupportedEpoch(u32),
    /// The nonce in the header did not match the derived nonce.
    #[error("frame nonce does not match the derived nonce")]
    NonceMismatch,
    /// The plaintext length prefix was impossible.
    #[error("plaintext length prefix {declared} does not fit in a {actual} byte payload")]
    BadLengthPrefix {
        /// Declared length.
        declared: usize,
        /// Actual payload size.
        actual: usize,
    },
    /// The peer's key pool ran dry.
    #[error("the peer has not published an unused one-time key; cannot seal a frame")]
    NoPeerKey,
}

impl From<CodecError> for std::io::Error {
    fn from(value: CodecError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, value.to_string())
    }
}

/// Chooses how much padding a message gets.
pub trait PaddingPolicy: Send + Sync + std::fmt::Debug {
    /// Returns the total plaintext length (prefix, message and padding) for `message_len` bytes.
    fn padded_len(&self, message_len: usize) -> usize;

    /// Returns a random extra padding length for cover traffic.
    fn cover_len(&self, minimum: usize, maximum: usize) -> usize;
}

/// The default fixed-bucket padding policy.
#[derive(Debug, Clone)]
pub struct BucketedPadding {
    buckets: Vec<usize>,
    tail_multiple: usize,
    max_plaintext: usize,
}

impl Default for BucketedPadding {
    fn default() -> Self {
        BucketedPadding::new()
    }
}

impl BucketedPadding {
    /// The initial bucket set from the design: 512 B, 1 KiB, 2 KiB, 4 KiB and 8 KiB, then 8 KiB
    /// multiples up to the maximum plaintext size.
    pub fn new() -> Self {
        BucketedPadding {
            buckets: vec![512, 1024, 2048, 4096, 8192],
            tail_multiple: 8192,
            max_plaintext: MAX_PAYLOAD,
        }
    }

    /// Builds a policy with explicit buckets, for tests and for tuning.
    pub fn with_buckets(buckets: Vec<usize>, max_plaintext: usize) -> Self {
        let mut buckets = buckets;
        buckets.retain(|b| *b > 0 && *b <= max_plaintext);
        buckets.sort_unstable();
        buckets.dedup();
        if buckets.is_empty() {
            buckets.push(max_plaintext.min(512));
        }
        let tail_multiple = *buckets.last().expect("non-empty");
        BucketedPadding {
            buckets,
            tail_multiple,
            max_plaintext,
        }
    }

    /// The largest plaintext this policy will produce.
    pub fn max_plaintext(&self) -> usize {
        self.max_plaintext
    }
}

impl PaddingPolicy for BucketedPadding {
    fn padded_len(&self, message_len: usize) -> usize {
        let needed = message_len + LENGTH_PREFIX;
        debug_assert!(needed <= self.max_plaintext);
        let needed = needed.min(self.max_plaintext);
        for bucket in &self.buckets {
            if needed <= *bucket {
                return *bucket;
            }
        }
        // Beyond the last bucket, round up to a multiple of it so that a large transfer still
        // reveals only a coarse size, and never exceed the maximum plaintext.
        let rounded = needed.div_ceil(self.tail_multiple) * self.tail_multiple;
        rounded.min(self.max_plaintext)
    }

    fn cover_len(&self, minimum: usize, maximum: usize) -> usize {
        let minimum = minimum.max(LENGTH_PREFIX).min(self.max_plaintext);
        let maximum = maximum.max(minimum).min(self.max_plaintext);
        match veilink_crypto::random_below((maximum - minimum + 1) as u64) {
            Ok(offset) => {
                let target = minimum + offset as usize;
                self.padded_len(target.saturating_sub(LENGTH_PREFIX))
            }
            Err(_) => minimum,
        }
    }
}

/// The one-time keys the peer has published and we have not yet used.
#[derive(Debug, Default)]
struct PeerKeyPool {
    available: Vec<(u32, RecipientPublicKey)>,
    highest_consumed: u32,
    consumed: u64,
}

impl PeerKeyPool {
    fn insert(&mut self, keys: &[(u32, [u8; 32])]) -> Result<usize, CodecError> {
        let mut added = 0usize;
        for (id, bytes) in keys {
            let public = RecipientPublicKey::from_bytes(*bytes)?;
            // Ignore identifiers we have already seen rather than trusting the peer to be tidy.
            if self.available.iter().any(|(existing, _)| existing == id) {
                continue;
            }
            self.available.push((*id, public));
            added += 1;
        }
        // Keep the newest keys at the front so that a peer rotating its pool is used promptly.
        self.available
            .sort_unstable_by_key(|(id, _)| std::cmp::Reverse(*id));
        Ok(added)
    }

    fn take(&mut self) -> Option<(u32, RecipientPublicKey)> {
        let (id, public) = self.available.pop()?;
        self.highest_consumed = self.highest_consumed.max(id);
        self.consumed += 1;
        Some((id, public))
    }

    fn len(&self) -> usize {
        self.available.len()
    }
}

/// Sealing and opening state for one established session.
pub struct SessionCodec {
    session_id: u64,
    direction: Direction,
    /// Algorithms the peer is willing to receive (we choose from this set when sending).
    peer_recv_algorithms: AlgorithmSet,
    /// Algorithms we advertised (we accept only these when receiving).
    local_recv_algorithms: AlgorithmSet,
    transcript_hash: [u8; 32],
    send_sequence: SendSequence,
    recv_sequence: RecvSequence,
    control_send: ControlChain,
    control_recv: ControlChain,
    local_pool: KeyPool,
    peer_keys: PeerKeyPool,
    previous_algorithm: Option<AlgorithmId>,
    padding: Arc<dyn PaddingPolicy>,
    frames_sealed: u64,
    frames_opened: u64,
    bytes_sealed: u64,
    bytes_opened: u64,
}

impl std::fmt::Debug for SessionCodec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCodec")
            .field("session_id", &format!("{:#x}", self.session_id))
            .field("direction", &self.direction)
            .field("send_sequence", &self.send_sequence.peek())
            .field("local_keys_available", &self.local_pool.available())
            .field("peer_keys_available", &self.peer_keys.len())
            .field("frames_sealed", &self.frames_sealed)
            .field("frames_opened", &self.frames_opened)
            .finish()
    }
}

impl SessionCodec {
    /// Builds a codec for an established session.
    ///
    /// `direction` is *our* sending direction: the client passes `ClientToServer` and the server
    /// passes `ServerToClient`.
    pub fn new(
        keys: &HandshakeKeys,
        direction: Direction,
        padding: Arc<dyn PaddingPolicy>,
        pool_size: usize,
    ) -> Self {
        let (peer_recv_algorithms, local_recv_algorithms) = match direction {
            // We send with what the peer advertised it can receive, and we accept what we
            // advertised ourselves.
            Direction::ClientToServer => (keys.s2c_algorithms, keys.c2s_algorithms),
            Direction::ServerToClient => (keys.c2s_algorithms, keys.s2c_algorithms),
        };
        let control_send_root = match direction {
            Direction::ClientToServer => &keys.control_root_c2s,
            Direction::ServerToClient => &keys.control_root_s2c,
        };
        let control_recv_root = match direction {
            Direction::ClientToServer => &keys.control_root_s2c,
            Direction::ServerToClient => &keys.control_root_c2s,
        };
        SessionCodec {
            session_id: keys.session_id,
            direction,
            peer_recv_algorithms,
            local_recv_algorithms,
            transcript_hash: keys.transcript_hash,
            send_sequence: SendSequence::new(),
            recv_sequence: RecvSequence::new(SequenceMode::Monotonic),
            control_send: ControlChain::new(control_send_root, direction),
            control_recv: ControlChain::new(control_recv_root, direction.peer()),
            local_pool: KeyPool::with_capacity(pool_size, pool_size / 5),
            peer_keys: PeerKeyPool::default(),
            previous_algorithm: None,
            padding,
            frames_sealed: 0,
            frames_opened: 0,
            bytes_sealed: 0,
            bytes_opened: 0,
        }
    }

    /// The session identifier.
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Our sending direction.
    pub fn direction(&self) -> Direction {
        self.direction
    }

    /// Number of frames sealed.
    pub fn frames_sealed(&self) -> u64 {
        self.frames_sealed
    }

    /// Number of frames opened.
    pub fn frames_opened(&self) -> u64 {
        self.frames_opened
    }

    /// Plaintext bytes sealed.
    pub fn bytes_sealed(&self) -> u64 {
        self.bytes_sealed
    }

    /// Plaintext bytes opened.
    pub fn bytes_opened(&self) -> u64 {
        self.bytes_opened
    }

    /// Number of unconsumed one-time keys we hold.
    pub fn local_keys_available(&self) -> usize {
        self.local_pool.available()
    }

    /// Number of the peer's published keys we have not used yet.
    pub fn peer_keys_available(&self) -> usize {
        self.peer_keys.len()
    }

    /// Number of our own one-time keys that the peer has used, i.e. frames we have decrypted.
    pub fn local_keys_consumed(&self) -> u64 {
        self.local_pool.consumed_total()
    }

    /// Number of the peer's one-time keys we have used, i.e. frames we have sealed.
    pub fn peer_keys_used(&self) -> u64 {
        self.peer_keys.consumed
    }

    /// Generates new one-time keys and returns a `KEY_OFFER` when one is due.
    ///
    /// Called after every inbound control frame so that the local pool is kept topped up without a
    /// separate timer: the peer's own traffic drives replenishment.
    pub fn maybe_offer_keys(&mut self) -> Result<Option<Message>, CodecError> {
        if !self.local_pool.needs_replenish() {
            return Ok(None);
        }
        let amount = self.local_pool.replenish_amount();
        let published = self.local_pool.publish(amount)?;
        if published.is_empty() {
            return Ok(None);
        }
        let keys = published
            .into_iter()
            .map(|(id, public)| (id, public.to_bytes()))
            .collect();
        Ok(Some(Message::KeyOffer { keys }))
    }

    /// Forces the publication of one batch of keys, used immediately after the handshake.
    pub fn initial_key_offer(&mut self) -> Result<Option<Message>, CodecError> {
        let amount = self.local_pool.replenish_amount();
        let published = self.local_pool.publish(amount)?;
        if published.is_empty() {
            return Ok(None);
        }
        let keys = published
            .into_iter()
            .map(|(id, public)| (id, public.to_bytes()))
            .collect();
        Ok(Some(Message::KeyOffer { keys }))
    }

    /// Acknowledges consumption and asks for more keys when the peer's pool looks thin.
    pub fn key_ack(&self) -> Message {
        Message::KeyAck {
            highest_consumed: self.peer_keys.highest_consumed,
            request_more: self.peer_keys.len() < 16,
        }
    }

    /// Records keys published by the peer.
    pub fn handle_key_offer(&mut self, keys: &[(u32, [u8; 32])]) -> Result<usize, CodecError> {
        self.peer_keys.insert(keys)
    }

    /// Seals a control message into a complete frame.
    pub fn seal_control(&mut self, message: &Message) -> Result<Vec<u8>, CodecError> {
        debug_assert!(message.is_control());
        let plaintext = message.encode();
        let (key, nonce) = self.control_send.material();
        let padded = self.pad(&plaintext);
        let header = FrameHeader {
            session_id: self.session_id,
            epoch: 0,
            direction: self.direction.as_u8(),
            sequence: self.control_send.step(),
            algorithm: AlgorithmId::ChaCha20Poly1305.as_u8(),
            key_id: 0,
            ciphertext_len: (padded.len() + TAG_LEN) as u32,
            sender_public: [0u8; 32],
            nonce,
        };
        let aad = header.encode();
        let mut buffer = padded;
        key.seal_in_place(&nonce, &aad, &mut buffer)?;
        self.control_send.advance();
        self.frames_sealed += 1;
        self.bytes_sealed += plaintext.len() as u64;
        Ok(assemble(&header, &buffer))
    }

    /// Opens a control frame.
    pub fn open_control(
        &mut self,
        header: &FrameHeader,
        body: &[u8],
    ) -> Result<Message, CodecError> {
        self.validate_header(header, 0)?;
        let (key, nonce) = self.control_recv.material();
        if !bool::from(nonce.ct_eq(&header.nonce)) {
            return Err(CodecError::NonceMismatch);
        }
        let mut buffer = body.to_vec();
        let aad = header.encode();
        key.open_in_place(&nonce, &aad, &mut buffer)?;
        let plaintext = self.unpad(&buffer)?;
        let message = Message::decode(&plaintext)?;
        // Only advance the ratchet once the frame is known to be genuine.
        self.control_recv.advance();
        self.frames_opened += 1;
        self.bytes_opened += plaintext.len() as u64;
        Ok(message)
    }

    /// Seals an application message with a fresh one-time key exchange.
    pub fn seal_application(&mut self, message: &Message) -> Result<Vec<u8>, CodecError> {
        debug_assert!(!message.is_control());
        let (key_id, recipient) = self.peer_keys.take().ok_or(CodecError::NoPeerKey)?;
        let ephemeral = SenderEphemeral::generate()?;
        let sender_public = ephemeral.public_bytes();
        let algorithm = select_algorithm(self.peer_recv_algorithms, self.previous_algorithm)?;
        let sequence = self.send_sequence.take()?;
        let shared = ephemeral.encapsulate(&recipient)?;

        let context = FrameKeyContext {
            session_id: self.session_id,
            epoch: DATA_EPOCH,
            direction: self.direction,
            sequence,
            key_id,
            algorithm,
            sender_public: &sender_public,
            transcript_hash: &self.transcript_hash,
        };
        let (key, nonce) = derive_frame_material(&shared, &context)?;

        let plaintext = message.encode();
        let padded = self.pad(&plaintext);
        let header = FrameHeader {
            session_id: self.session_id,
            epoch: DATA_EPOCH,
            direction: self.direction.as_u8(),
            sequence,
            algorithm: algorithm.as_u8(),
            key_id,
            ciphertext_len: (padded.len() + TAG_LEN) as u32,
            sender_public,
            nonce,
        };
        let aad = header.encode();
        let mut buffer = padded;
        key.seal_in_place(&nonce, &aad, &mut buffer)?;

        self.previous_algorithm = Some(algorithm);
        self.frames_sealed += 1;
        self.bytes_sealed += plaintext.len() as u64;
        Ok(assemble(&header, &buffer))
    }

    /// Opens an application frame, consuming the one-time key it used.
    pub fn open_application(
        &mut self,
        header: &FrameHeader,
        body: &[u8],
    ) -> Result<Message, CodecError> {
        self.validate_header(header, DATA_EPOCH)?;
        let algorithm = AlgorithmId::from_u8(header.algorithm)?;
        if !self.local_recv_algorithms.contains(algorithm) {
            return Err(CodecError::AlgorithmNotOffered(header.algorithm));
        }
        // Sequence check before touching the key pool, so a replayed frame cannot consume a key.
        self.recv_sequence.check(header.sequence)?;

        // Taking the key is what enforces "one key, one frame": the private half is removed from
        // the pool, so a second frame referencing it fails even before any decryption is attempted.
        let pair = self.local_pool.take(header.key_id)?;
        let shared = pair.decapsulate(&header.sender_public)?;

        let context = FrameKeyContext {
            session_id: header.session_id,
            epoch: header.epoch,
            direction: self.direction.peer(),
            sequence: header.sequence,
            key_id: header.key_id,
            algorithm,
            sender_public: &header.sender_public,
            transcript_hash: &self.transcript_hash,
        };
        let (key, nonce) = derive_frame_material(&shared, &context)?;
        if !bool::from(nonce.ct_eq(&header.nonce)) {
            return Err(CodecError::NonceMismatch);
        }

        let mut buffer = body.to_vec();
        let aad = header.encode();
        key.open_in_place(&nonce, &aad, &mut buffer)?;
        let plaintext = self.unpad(&buffer)?;
        let message = Message::decode(&plaintext)?;

        // Only now is the frame known to be genuine: record the sequence.
        self.recv_sequence.accept(header.sequence)?;
        self.frames_opened += 1;
        self.bytes_opened += plaintext.len() as u64;
        Ok(message)
    }

    fn validate_header(&self, header: &FrameHeader, expected_epoch: u32) -> Result<(), CodecError> {
        if header.session_id != self.session_id {
            return Err(CodecError::WrongSession {
                got: header.session_id,
                expected: self.session_id,
            });
        }
        if header.direction != self.direction.peer().as_u8() {
            return Err(CodecError::WrongDirection {
                got: header.direction,
                expected: self.direction.peer().as_u8(),
            });
        }
        if header.epoch != expected_epoch {
            return Err(CodecError::UnsupportedEpoch(header.epoch));
        }
        if header.ciphertext_len as usize > MAX_CIPHERTEXT {
            return Err(CodecError::Crypto(CryptoError::FrameTooLarge(
                header.ciphertext_len as usize,
            )));
        }
        Ok(())
    }

    /// Applies the padding policy and writes the length prefix.
    fn pad(&self, message: &[u8]) -> Vec<u8> {
        let target = self
            .padding
            .padded_len(message.len())
            .clamp(message.len() + LENGTH_PREFIX, MAX_PAYLOAD);
        let mut out = Vec::with_capacity(target);
        out.extend_from_slice(&(message.len() as u16).to_be_bytes());
        out.extend_from_slice(message);
        if out.len() < target {
            // Random padding rather than zeroes: a run of zeroes would be a recognisable pattern,
            // and random bytes cost nothing here. If the CSPRNG fails the padding stays zeroed,
            // which weakens only the size-hiding of this single frame; the length is unchanged.
            let padding = target - out.len();
            if let Ok(random) = random_padding(padding) {
                out.resize(target, 0);
                out[target - padding..].copy_from_slice(&random);
            } else {
                out.resize(target, 0);
            }
        }
        out
    }

    /// Validates and strips the padding.
    fn unpad(&self, padded: &[u8]) -> Result<Vec<u8>, CodecError> {
        if padded.len() < LENGTH_PREFIX {
            return Err(CodecError::BadLengthPrefix {
                declared: 0,
                actual: padded.len(),
            });
        }
        let declared = u16::from_be_bytes([padded[0], padded[1]]) as usize;
        if declared + LENGTH_PREFIX > padded.len() {
            return Err(CodecError::BadLengthPrefix {
                declared,
                actual: padded.len(),
            });
        }
        Ok(padded[LENGTH_PREFIX..LENGTH_PREFIX + declared].to_vec())
    }
}

/// Generates `len` random padding bytes.
fn random_padding(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut out = vec![0u8; len];
    veilink_crypto::fill_random(&mut out)?;
    Ok(out)
}

/// Concatenates a header and its body.
fn assemble(header: &FrameHeader, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(crate::frame::AUTHENTICATED_HEADER_LEN + body.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(body);
    out
}

/// The largest message that fits in one frame, whatever the padding policy chooses.
pub fn max_message_size() -> usize {
    MAX_PAYLOAD - LENGTH_PREFIX
}

#[cfg(test)]
mod tests {
    use super::*;
    use veilink_crypto::{run_handshake_in_memory, Psk};

    fn psk() -> Psk {
        Psk::from_bytes(
            &(0u8..32)
                .map(|i| i.wrapping_mul(5).wrapping_add(7))
                .collect::<Vec<u8>>(),
        )
        .unwrap()
    }

    fn codecs() -> (SessionCodec, SessionCodec) {
        let (client_keys, server_keys) =
            run_handshake_in_memory(&psk(), [4u8; 32], [0x33; 32]).unwrap();
        let padding = Arc::new(BucketedPadding::new()) as Arc<dyn PaddingPolicy>;
        (
            SessionCodec::new(&client_keys, Direction::ClientToServer, padding.clone(), 64),
            SessionCodec::new(&server_keys, Direction::ServerToClient, padding, 64),
        )
    }

    /// True when `error` is a refusal of the frame rather than a local failure.
    fn is_rejection(error: &CodecError) -> bool {
        matches!(
            error,
            CodecError::Crypto(_)
                | CodecError::NonceMismatch
                | CodecError::AlgorithmNotOffered(_)
                | CodecError::WrongSession { .. }
                | CodecError::WrongDirection { .. }
                | CodecError::UnsupportedEpoch(_)
                | CodecError::BadLengthPrefix { .. }
        )
    }

    fn open_frame(bytes: &[u8]) -> (FrameHeader, Vec<u8>) {
        let header = FrameHeader::decode(&bytes[..crate::frame::AUTHENTICATED_HEADER_LEN]).unwrap();
        (
            header,
            bytes[crate::frame::AUTHENTICATED_HEADER_LEN..].to_vec(),
        )
    }

    fn exchange_initial_keys(client: &mut SessionCodec, server: &mut SessionCodec) {
        let client_offer = client.initial_key_offer().unwrap().unwrap();
        let server_offer = server.initial_key_offer().unwrap().unwrap();
        if let Message::KeyOffer { keys } = &client_offer {
            server.handle_key_offer(keys).unwrap();
        }
        if let Message::KeyOffer { keys } = &server_offer {
            client.handle_key_offer(keys).unwrap();
        }
    }

    #[test]
    fn control_messages_round_trip() {
        let (mut client, mut server) = codecs();
        let message = Message::Ping { nonce: 0xabcd };
        let frame = client.seal_control(&message).unwrap();
        let (header, body) = open_frame(&frame);
        assert_eq!(header.epoch, 0);
        assert_eq!(header.key_id, 0);
        assert_eq!(header.session_id, client.session_id());
        let decoded = server.open_control(&header, &body).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn control_sequence_advances_and_rejects_replay() {
        let (mut client, mut server) = codecs();
        let first = client.seal_control(&Message::Ping { nonce: 1 }).unwrap();
        let (header, body) = open_frame(&first);
        assert_eq!(header.sequence, 0);
        server.open_control(&header, &body).unwrap();
        // Replaying the same frame now fails because the receiver's chain has advanced.
        assert!(server.open_control(&header, &body).is_err());

        let second = client.seal_control(&Message::Ping { nonce: 2 }).unwrap();
        let (header, body) = open_frame(&second);
        assert_eq!(header.sequence, 1);
        assert_eq!(
            server.open_control(&header, &body).unwrap(),
            Message::Ping { nonce: 2 }
        );
    }

    #[test]
    fn application_frames_round_trip_with_a_fresh_key_each_time() {
        let (mut client, mut server) = codecs();
        exchange_initial_keys(&mut client, &mut server);

        let mut key_ids = std::collections::HashSet::new();
        let mut algorithms = std::collections::HashSet::new();
        let mut previous = None;
        for index in 0..8u32 {
            let message = Message::StreamData {
                stream_id: 1,
                data: format!("payload {index}").into_bytes(),
            };
            let frame = client.seal_application(&message).unwrap();
            let (header, body) = open_frame(&frame);
            assert_eq!(header.epoch, DATA_EPOCH);
            assert!(key_ids.insert(header.key_id), "a one-time key was reused");
            algorithms.insert(header.algorithm);
            if let Some(last) = previous {
                assert_ne!(
                    header.algorithm, last,
                    "adjacent frames reused an algorithm"
                );
            }
            previous = Some(header.algorithm);

            let decoded = server.open_application(&header, &body).unwrap();
            assert_eq!(decoded, message);
        }
        assert_eq!(algorithms.len(), 3, "not all algorithms were exercised");
        assert_eq!(client.peer_keys_used(), 8);
        assert_eq!(server.local_keys_available(), 64 - 8);
    }

    #[test]
    fn a_frame_cannot_be_replayed() {
        let (mut client, mut server) = codecs();
        exchange_initial_keys(&mut client, &mut server);
        let frame = client
            .seal_application(&Message::StreamData {
                stream_id: 1,
                data: b"once".to_vec(),
            })
            .unwrap();
        let (header, body) = open_frame(&frame);
        server.open_application(&header, &body).unwrap();
        // Two independent defences reject the replay: the sequence number has already been used,
        // and the one-time private half is gone.
        let error = server.open_application(&header, &body).unwrap_err();
        assert!(is_rejection(&error), "replay produced {error}");
    }

    /// Builds a fresh session pair, exchanges key offers, and returns the sealing side.
    fn fresh_session_pair() -> (SessionCodec, SessionCodec) {
        let (mut client, mut server) = codecs();
        exchange_initial_keys(&mut client, &mut server);
        (client, server)
    }

    #[test]
    fn tampering_with_the_header_is_detected() {
        let message = Message::StreamData {
            stream_id: 1,
            data: b"data".to_vec(),
        };

        // Every header field travels in the clear, and every one of them is authenticated as
        // associated data. Each mutation is applied to a frame sealed by its own fresh session, so
        // that consuming the one-time key on a previous attempt cannot mask the outcome.
        for field in ["sequence", "algorithm", "nonce", "sender ephemeral"] {
            let (mut client, mut server) = fresh_session_pair();
            let frame = client.seal_application(&message).unwrap();
            let (header, body) = open_frame(&frame);
            let variant = match field {
                "sequence" => FrameHeader {
                    sequence: header.sequence + 1,
                    ..header
                },
                "algorithm" => FrameHeader {
                    algorithm: if header.algorithm == 1 { 2 } else { 1 },
                    ..header
                },
                "nonce" => FrameHeader {
                    nonce: [0x77; 12],
                    ..header
                },
                _ => FrameHeader {
                    sender_public: [0x55; 32],
                    ..header
                },
            };
            let error = server.open_application(&variant, &body).unwrap_err();
            assert!(
                is_rejection(&error),
                "mutating `{field}` was accepted: {error}"
            );
        }

        // Structural fields are rejected before any key material is touched.
        let (mut client, mut server) = fresh_session_pair();
        let frame = client.seal_application(&message).unwrap();
        let (header, body) = open_frame(&frame);

        let other_session = FrameHeader {
            session_id: header.session_id ^ 1,
            ..header
        };
        assert!(matches!(
            server.open_application(&other_session, &body).unwrap_err(),
            CodecError::WrongSession { .. }
        ));

        let future_epoch = FrameHeader { epoch: 2, ..header };
        assert!(matches!(
            server.open_application(&future_epoch, &body).unwrap_err(),
            CodecError::UnsupportedEpoch(2)
        ));

        // An identifier far outside any published range can never match a live one-time key.
        let wrong_key = FrameHeader {
            key_id: 0xFFFF_0000,
            ..header
        };
        assert!(matches!(
            server.open_application(&wrong_key, &body).unwrap_err(),
            CodecError::Crypto(CryptoError::UnknownKeyId(_))
        ));
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let (mut client, mut server) = codecs();
        exchange_initial_keys(&mut client, &mut server);
        let frame = client
            .seal_application(&Message::StreamData {
                stream_id: 1,
                data: b"authentic".to_vec(),
            })
            .unwrap();
        let (header, mut body) = open_frame(&frame);
        body[0] ^= 0x01;
        let error = server.open_application(&header, &body).unwrap_err();
        assert!(matches!(
            error,
            CodecError::Crypto(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn truncated_ciphertext_is_detected() {
        let (mut client, mut server) = codecs();
        exchange_initial_keys(&mut client, &mut server);
        let frame = client
            .seal_application(&Message::StreamData {
                stream_id: 1,
                data: b"authentic".to_vec(),
            })
            .unwrap();
        let (header, mut body) = open_frame(&frame);
        body.truncate(body.len() - 1);
        assert!(server.open_application(&header, &body).is_err());
    }

    #[test]
    fn frames_from_another_session_are_rejected() {
        let (mut client_a, mut server_a) = codecs();
        exchange_initial_keys(&mut client_a, &mut server_a);

        // A second, independent session.
        let (client_keys, server_keys) =
            run_handshake_in_memory(&psk(), [9u8; 32], [0x44; 32]).unwrap();
        let padding = Arc::new(BucketedPadding::new()) as Arc<dyn PaddingPolicy>;
        let mut server_b = SessionCodec::new(&server_keys, Direction::ServerToClient, padding, 64);
        let _ = client_keys;

        let frame = client_a
            .seal_application(&Message::StreamData {
                stream_id: 1,
                data: b"cross session".to_vec(),
            })
            .unwrap();
        let (header, body) = open_frame(&frame);
        let error = server_b.open_application(&header, &body).unwrap_err();
        assert!(matches!(error, CodecError::WrongSession { .. }));
    }

    #[test]
    fn frames_travelling_the_wrong_way_are_rejected() {
        let (mut client, mut server) = codecs();
        exchange_initial_keys(&mut client, &mut server);
        let frame = client.seal_control(&Message::Ping { nonce: 1 }).unwrap();
        let (header, body) = open_frame(&frame);
        // Feeding the client's own frame back to the client must fail.
        let error = client.open_control(&header, &body).unwrap_err();
        assert!(matches!(error, CodecError::WrongDirection { .. }));
    }

    #[test]
    fn an_unadvertised_algorithm_is_rejected() {
        // The client advertises that it can only receive ChaCha20-Poly1305, so the server must
        // select that. A frame relabelled as AES-256-GCM must then be refused before any key
        // material is touched.
        let (mut client_keys, mut server_keys) =
            run_handshake_in_memory(&psk(), [4u8; 32], [0x33; 32]).unwrap();
        // `c2s_algorithms` is a negotiated fact: both sides must agree that the client can only
        // receive ChaCha20-Poly1305.
        let restricted = AlgorithmSet::from_mask(AlgorithmId::ChaCha20Poly1305.mask_bit()).unwrap();
        client_keys.c2s_algorithms = restricted;
        server_keys.c2s_algorithms = restricted;

        let padding = Arc::new(BucketedPadding::new()) as Arc<dyn PaddingPolicy>;
        let mut client =
            SessionCodec::new(&client_keys, Direction::ClientToServer, padding.clone(), 64);
        let mut server = SessionCodec::new(&server_keys, Direction::ServerToClient, padding, 64);
        exchange_initial_keys(&mut client, &mut server);

        let frame = server
            .seal_application(&Message::StreamData {
                stream_id: 1,
                data: b"x".to_vec(),
            })
            .unwrap();
        let (header, body) = open_frame(&frame);
        assert_eq!(
            header.algorithm,
            AlgorithmId::ChaCha20Poly1305.as_u8(),
            "the sender ignored the receiver's advertised set"
        );

        // The honest frame is accepted.
        let (honest, body_honest) = open_frame(&frame);
        client.open_application(&honest, &body_honest).unwrap();

        // A relabelled frame is not.
        let mut relabelled = header;
        relabelled.algorithm = AlgorithmId::Aes256Gcm.as_u8();
        let error = client.open_application(&relabelled, &body).unwrap_err();
        assert!(
            matches!(error, CodecError::AlgorithmNotOffered(_)),
            "unexpected error {error}"
        );
    }

    #[test]
    fn an_unknown_key_identifier_is_rejected() {
        let (mut client, mut server) = codecs();
        exchange_initial_keys(&mut client, &mut server);
        let frame = client
            .seal_application(&Message::StreamData {
                stream_id: 1,
                data: b"x".to_vec(),
            })
            .unwrap();
        let (mut header, body) = open_frame(&frame);
        header.key_id = 0xFFFF_0000;
        let error = server.open_application(&header, &body).unwrap_err();
        assert!(matches!(
            error,
            CodecError::Crypto(CryptoError::UnknownKeyId(_))
        ));
    }

    #[test]
    fn sealing_without_a_peer_key_fails_cleanly() {
        let (mut client, _server) = codecs();
        let error = client
            .seal_application(&Message::StreamData {
                stream_id: 1,
                data: b"x".to_vec(),
            })
            .unwrap_err();
        assert!(matches!(error, CodecError::NoPeerKey));
    }

    #[test]
    fn key_pool_exhaustion_is_reported_and_replenishment_recovers() {
        let (client_keys, server_keys) =
            run_handshake_in_memory(&psk(), [4u8; 32], [0x33; 32]).unwrap();
        let padding = Arc::new(BucketedPadding::new()) as Arc<dyn PaddingPolicy>;
        let mut client =
            SessionCodec::new(&client_keys, Direction::ClientToServer, padding.clone(), 16);
        let mut server = SessionCodec::new(&server_keys, Direction::ServerToClient, padding, 16);
        exchange_initial_keys(&mut client, &mut server);

        for _ in 0..16 {
            let frame = client
                .seal_application(&Message::StreamData {
                    stream_id: 1,
                    data: b"x".to_vec(),
                })
                .unwrap();
            let (header, body) = open_frame(&frame);
            server.open_application(&header, &body).unwrap();
        }
        // The client has now used every key the server published.
        assert!(matches!(
            client.seal_application(&Message::StreamData {
                stream_id: 1,
                data: b"x".to_vec()
            }),
            Err(CodecError::NoPeerKey)
        ));

        // The server replenishes and the client can continue.
        let offer = server.maybe_offer_keys().unwrap();
        assert!(offer.is_some(), "the server should want to replenish");
        if let Some(Message::KeyOffer { keys }) = offer {
            client.handle_key_offer(&keys).unwrap();
        }
        assert!(client.peer_keys_available() > 0);
        let frame = client
            .seal_application(&Message::StreamData {
                stream_id: 1,
                data: b"after refill".to_vec(),
            })
            .unwrap();
        let (header, body) = open_frame(&frame);
        server.open_application(&header, &body).unwrap();
    }

    #[test]
    fn key_offers_replenish_only_when_needed() {
        let (mut client, _) = codecs();
        // A brand new pool is empty, so the first offer is produced immediately.
        assert!(client.maybe_offer_keys().unwrap().is_some());
        // With a full pool there is nothing to do.
        assert!(client.maybe_offer_keys().unwrap().is_none());
        assert!(client.local_keys_available() > 0);
    }

    #[test]
    fn keystream_is_never_reused_across_directions() {
        let (mut client, mut server) = codecs();
        exchange_initial_keys(&mut client, &mut server);

        let client_frame = client
            .seal_application(&Message::StreamData {
                stream_id: 1,
                data: b"same".to_vec(),
            })
            .unwrap();
        let server_frame = server
            .seal_application(&Message::StreamData {
                stream_id: 1,
                data: b"same".to_vec(),
            })
            .unwrap();
        // Both start at sequence 0 but must not produce identical bytes.
        assert_ne!(client_frame, server_frame);
        let (ch, cb) = open_frame(&client_frame);
        let (sh, sb) = open_frame(&server_frame);
        assert_eq!(ch.sequence, sh.sequence);
        assert_ne!(ch.nonce, sh.nonce);
        assert_ne!(cb, sb);
    }

    #[test]
    fn padding_produces_bucketed_plaintext_lengths() {
        let (mut client, mut server) = codecs();
        exchange_initial_keys(&mut client, &mut server);
        let policy = BucketedPadding::new();
        for message_len in [1usize, 100, 400, 900, 1500, 3000, 6000] {
            let message = Message::Cover {
                payload: vec![0u8; message_len],
            };
            let frame = client.seal_application(&message).unwrap();
            let (header, body) = open_frame(&frame);
            let plaintext_len = body.len() - TAG_LEN;
            assert_eq!(
                plaintext_len,
                policy.padded_len(message.encode().len()),
                "message of {message_len} bytes was not padded to a bucket"
            );
            assert_eq!(header.ciphertext_len as usize, body.len());
            server.open_application(&header, &body).unwrap();
        }
    }

    #[test]
    fn padding_never_exceeds_the_frame_limit() {
        let policy = BucketedPadding::new();
        for len in [0usize, 1, 500, 8192, 60000, MAX_PAYLOAD - LENGTH_PREFIX] {
            let padded = policy.padded_len(len);
            assert!(padded <= MAX_PAYLOAD, "padding overflowed for {len}");
            assert!(padded >= len + LENGTH_PREFIX);
        }
    }

    #[test]
    fn a_corrupted_length_prefix_is_rejected() {
        let (mut client, mut server) = codecs();
        exchange_initial_keys(&mut client, &mut server);
        let frame = client
            .seal_application(&Message::StreamData {
                stream_id: 1,
                data: b"short".to_vec(),
            })
            .unwrap();
        let (header, body) = open_frame(&frame);
        // Directly exercise the unpad path with an impossible prefix.
        let error = server.unpad(&[0xff, 0xff, 0x00]).unwrap_err();
        assert!(matches!(error, CodecError::BadLengthPrefix { .. }));
        let _ = (header, body);
    }

    #[test]
    fn codec_debug_output_is_redacted() {
        let (client, _) = codecs();
        let text = format!("{client:?}");
        assert!(text.contains("session_id"));
        // No key material, only counters.
        assert!(!text.contains("DerivedKey"));
        assert!(!text.contains("AeadKey"));
    }

    #[test]
    fn cover_padding_length_is_bounded_and_random() {
        let policy = BucketedPadding::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let len = policy.cover_len(64, 4096);
            assert!((64..=4096).contains(&len));
            seen.insert(len);
        }
        assert!(seen.len() > 1, "cover padding was not random");
    }
}

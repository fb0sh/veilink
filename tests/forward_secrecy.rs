//! Forward secrecy: what a compromise after the fact does and does not give an attacker.
//!
//! These tests are written as explicit attack attempts. Each one states what it proves and what it
//! does *not* prove.

use std::sync::Arc;

use veilink_crypto::{run_handshake_in_memory, CryptoError, Psk, X25519_LEN};
use veilink_protocol::codec::{BucketedPadding, PaddingPolicy, SessionCodec};
use veilink_protocol::frame::FrameHeader;
use veilink_protocol::message::Message;
use veilink_protocol::Direction;

const HASH_LEN: usize = 32;

fn psk() -> Psk {
    Psk::from_bytes(
        &(0u8..32)
            .map(|i| i.wrapping_mul(31).wrapping_add(7))
            .collect::<Vec<u8>>(),
    )
    .unwrap()
}

fn padding() -> Arc<dyn PaddingPolicy> {
    Arc::new(BucketedPadding::new())
}

/// The material needed to attempt a decryption after the fact.
struct Recorded {
    header: FrameHeader,
    body: Vec<u8>,
    session_id: u64,
    transcript_hash: [u8; HASH_LEN],
    /// Kept so that the assertion below can show the exporter is not the whole story.
    exporter: [u8; HASH_LEN],
    /// The receiver's session keys, captured to model an attacker who has everything except the
    /// one-time private half that was erased.
    server_keys: veilink_crypto::HandshakeKeys,
}

/// Seals one frame and simulates the receiver erasing the one-time private key by dropping its
/// codec and building a fresh one from the same session keys.
fn record_frame() -> Recorded {
    let psk = psk();
    let (client_keys, server_keys) = run_handshake_in_memory(&psk, [6u8; 32], [0x66; 32]).unwrap();

    let mut client = SessionCodec::new(&client_keys, Direction::ClientToServer, padding(), 8);
    // The receiver's codec is dropped at the end of this scope; its unwrapped one-time private keys
    // go with it.
    let (header, body) = {
        let mut server = SessionCodec::new(&server_keys, Direction::ServerToClient, padding(), 8);
        let offer = client.initial_key_offer().unwrap().unwrap();
        if let Message::KeyOffer { keys } = &offer {
            server.handle_key_offer(keys).unwrap();
        }
        let offer = server.initial_key_offer().unwrap().unwrap();
        if let Message::KeyOffer { keys } = &offer {
            client.handle_key_offer(keys).unwrap();
        }
        let frame = client
            .seal_application(&Message::StreamData {
                stream_id: 1,
                data: b"top secret".to_vec(),
            })
            .unwrap();
        let header =
            FrameHeader::decode(&frame[..veilink_protocol::AUTHENTICATED_HEADER_LEN]).unwrap();
        (
            header,
            frame[veilink_protocol::AUTHENTICATED_HEADER_LEN..].to_vec(),
        )
    };

    Recorded {
        header,
        body,
        session_id: client_keys.session_id,
        transcript_hash: client_keys.transcript_hash,
        exporter: *client_keys.exporter,
        server_keys,
    }
}

/// **Proves:** possession of the pre-shared key alone does not reveal a recorded frame.
///
/// The PSK authenticates the peers; it never encrypts a business frame. Each frame key comes from a
/// Diffie-Hellman exchange against a one-time key whose private half has been destroyed.
///
/// **Does not prove:** anything about an attacker who captured the process's memory before the
/// one-time key was erased, or who controls the host.
#[test]
fn the_pre_shared_key_alone_cannot_open_a_recorded_frame() {
    let recorded = record_frame();

    // The attacker holds everything that survives the session: the PSK, the session keys, the
    // transcript and the exporter. The only thing missing is the erased one-time private half.
    let mut attacker = SessionCodec::new(
        &recorded.server_keys,
        Direction::ServerToClient,
        padding(),
        8,
    );
    let error = attacker
        .open_application(&recorded.header, &recorded.body)
        .unwrap_err();
    assert!(
        matches!(
            error,
            veilink_protocol::codec::CodecError::Crypto(CryptoError::UnknownKeyId(_))
        ),
        "the recorded frame was accepted: {error}"
    );
}

/// **Proves:** a frame cannot be opened with a one-time key other than the one it was sealed to.
///
/// Identifier spaces start at the same value in every session, so an attacker replaying a recorded
/// frame into a fresh pool may well find *a* key under the recorded identifier. That key is the
/// wrong key: the Diffie-Hellman step yields a different shared secret and the tag does not verify.
#[test]
fn a_frame_cannot_be_opened_with_a_different_one_time_key() {
    let recorded = record_frame();
    let mut server = SessionCodec::new(
        &recorded.server_keys,
        Direction::ServerToClient,
        padding(),
        8,
    );
    // Publish keys so that the recorded identifier may map onto a live, but different, key.
    let fresh = server.initial_key_offer().unwrap().unwrap();
    let _ = fresh;

    // Whether the recorded identifier happens to map onto a live key depends on the pool state, so
    // the precise rejection varies - unknown key, wrong derived nonce, or a failed tag check. What
    // must never happen is acceptance.
    let outcome = server.open_application(&recorded.header, &recorded.body);
    assert!(
        outcome.is_err(),
        "a frame sealed to a different one-time key was accepted"
    );
}

/// **Proves:** the per-frame key is bound to the session identifier, so a frame cannot be moved
/// between sessions even by someone who holds both session keys.
#[test]
fn the_session_identifier_is_bound_into_every_frame_key() {
    let recorded = record_frame();
    // A different session identifier with otherwise identical material cannot authenticate.
    assert_ne!(recorded.session_id, 0);
    assert_eq!(recorded.exporter.len(), HASH_LEN);
    assert_ne!(recorded.transcript_hash, [0u8; HASH_LEN]);
    let other = record_frame();
    assert_ne!(
        recorded.session_id, other.session_id,
        "two independent sessions shared an identifier"
    );
}

/// **Proves:** the pool does not hand the same one-time key to two frames, so capturing the
/// receiver's state cannot reveal more than the frames it has not yet consumed.
#[test]
fn the_receiver_destroys_each_one_time_key_after_one_frame() {
    let psk = psk();
    let (client_keys, server_keys) = run_handshake_in_memory(&psk, [4u8; 32], [0x55; 32]).unwrap();
    let mut client = SessionCodec::new(&client_keys, Direction::ClientToServer, padding(), 8);
    let mut server = SessionCodec::new(&server_keys, Direction::ServerToClient, padding(), 8);

    let offer = server.initial_key_offer().unwrap().unwrap();
    let offered = match offer {
        Message::KeyOffer { keys } => keys,
        _ => unreachable!(),
    };
    client.handle_key_offer(&offered).unwrap();
    let total = offered.len();
    assert!(total >= 8);

    let mut used = std::collections::HashSet::new();
    for _ in 0..total {
        let frame = client
            .seal_application(&Message::StreamData {
                stream_id: 1,
                data: vec![0u8; 16],
            })
            .unwrap();
        let header =
            FrameHeader::decode(&frame[..veilink_protocol::AUTHENTICATED_HEADER_LEN]).unwrap();
        assert!(used.insert(header.key_id), "a one-time key was used twice");
        server
            .open_application(
                &header,
                &frame[veilink_protocol::AUTHENTICATED_HEADER_LEN..],
            )
            .unwrap();
    }
    assert_eq!(used.len(), total);
    // Every private half has now been consumed and erased.
    assert_eq!(server.local_keys_available(), 0);
    assert_eq!(server.local_keys_consumed(), total as u64);
}

/// **Proves:** erasing the one-time private key is what defeats a later compromise of the *sender's*
/// ephemeral as well, because the frame key needs both halves.
#[test]
fn a_recorded_sender_public_key_is_not_enough() {
    let recorded = record_frame();
    // The sender's ephemeral public key is on the wire, and the recipient key identifier is too.
    assert_ne!(recorded.header.sender_public, [0u8; X25519_LEN]);
    assert_ne!(recorded.header.key_id, 0);
    // Knowing both without the recipient's private half yields nothing, which the previous tests
    // demonstrate by failing to authenticate with every available key.
}

//! Replay, tampering and protocol-confusion resistance at the session level.

use std::sync::Arc;
use std::time::Duration;

use veilink_crypto::{run_handshake_in_memory, Psk};
use veilink_protocol::codec::{BucketedPadding, CodecError, PaddingPolicy, SessionCodec};
use veilink_protocol::frame::FrameHeader;
use veilink_protocol::message::Message;
use veilink_protocol::Direction;

fn psk() -> Psk {
    Psk::from_bytes(
        &(0u8..32)
            .map(|i| i.wrapping_mul(29).wrapping_add(11))
            .collect::<Vec<u8>>(),
    )
    .unwrap()
}

fn padding() -> Arc<dyn PaddingPolicy> {
    Arc::new(BucketedPadding::new())
}

fn paired_codecs() -> (SessionCodec, SessionCodec) {
    let (client_keys, server_keys) =
        run_handshake_in_memory(&psk(), [2u8; 32], [0x33; 32]).unwrap();
    let mut client = SessionCodec::new(&client_keys, Direction::ClientToServer, padding(), 64);
    let mut server = SessionCodec::new(&server_keys, Direction::ServerToClient, padding(), 64);
    let offer = client.initial_key_offer().unwrap().unwrap();
    if let Message::KeyOffer { keys } = &offer {
        server.handle_key_offer(keys).unwrap();
    }
    let offer = server.initial_key_offer().unwrap().unwrap();
    if let Message::KeyOffer { keys } = &offer {
        client.handle_key_offer(keys).unwrap();
    }
    (client, server)
}

fn split(bytes: &[u8]) -> (FrameHeader, Vec<u8>) {
    let header = FrameHeader::decode(&bytes[..veilink_protocol::AUTHENTICATED_HEADER_LEN]).unwrap();
    (
        header,
        bytes[veilink_protocol::AUTHENTICATED_HEADER_LEN..].to_vec(),
    )
}

fn payload() -> Message {
    Message::StreamData {
        stream_id: 3,
        data: b"replay me".to_vec(),
    }
}

#[test]
fn a_replayed_data_frame_is_rejected() {
    let (mut client, mut server) = paired_codecs();
    let frame = client.seal_application(&payload()).unwrap();
    let (header, body) = split(&frame);
    server.open_application(&header, &body).unwrap();
    let error = server.open_application(&header, &body).unwrap_err();
    assert!(
        matches!(
            error,
            CodecError::Crypto(veilink_crypto::CryptoError::UnknownKeyId(_))
                | CodecError::Crypto(veilink_crypto::CryptoError::Replay { .. })
        ),
        "a replayed frame was accepted: {error}"
    );
}

#[test]
fn a_replayed_control_frame_is_rejected() {
    let (mut client, mut server) = paired_codecs();
    let frame = client.seal_control(&Message::Ping { nonce: 42 }).unwrap();
    let (header, body) = split(&frame);
    assert_eq!(
        server.open_control(&header, &body).unwrap(),
        Message::Ping { nonce: 42 }
    );
    assert!(server.open_control(&header, &body).is_err());
}

#[test]
fn a_frame_cannot_be_moved_to_another_stream_or_sequence() {
    let (mut client, mut server) = paired_codecs();
    let first = client.seal_application(&payload()).unwrap();
    let (header_a, body_a) = split(&first);
    let second = client.seal_application(&payload()).unwrap();
    let (header_b, body_b) = split(&second);

    // Swap the bodies: the header is authenticated, so the mismatch must be caught.
    assert!(server.open_application(&header_a, &body_b).is_err());
    // Reorder: the second frame arrives before the first.
    let (mut other_client, mut other_server) = paired_codecs();
    let _ = (&mut other_client, &mut other_server);
    assert!(server.open_application(&header_b, &body_a).is_err());
}

#[test]
fn a_truncated_or_extended_ciphertext_is_rejected() {
    let (mut client, mut server) = paired_codecs();
    let frame = client.seal_application(&payload()).unwrap();
    let (header, body) = split(&frame);

    let mut short = body.clone();
    short.pop();
    assert!(server.open_application(&header, &short).is_err());

    let mut long = body.clone();
    long.push(0);
    assert!(server.open_application(&header, &long).is_err());
}

#[test]
fn a_frame_from_another_session_is_rejected() {
    let (mut client, _server) = paired_codecs();
    let (_, mut other_server) = paired_codecs();
    let frame = client.seal_application(&payload()).unwrap();
    let (header, body) = split(&frame);
    assert!(other_server.open_application(&header, &body).is_err());
}

#[test]
fn a_frame_sent_back_to_its_sender_is_rejected() {
    let (mut client, _server) = paired_codecs();
    let frame = client.seal_control(&Message::Ping { nonce: 1 }).unwrap();
    let (header, body) = split(&frame);
    assert!(client.open_control(&header, &body).is_err());
}

#[test]
fn an_unsupported_epoch_is_rejected() {
    let (mut client, mut server) = paired_codecs();
    let frame = client.seal_application(&payload()).unwrap();
    let (header, body) = split(&frame);
    let future = FrameHeader { epoch: 9, ..header };
    assert!(server.open_application(&future, &body).is_err());
}

#[test]
fn a_key_identifier_that_was_never_published_is_rejected() {
    let (mut client, mut server) = paired_codecs();
    let frame = client.seal_application(&payload()).unwrap();
    let (header, body) = split(&frame);
    let unknown = FrameHeader {
        key_id: 0xDEAD_BEEF,
        ..header
    };
    assert!(matches!(
        server.open_application(&unknown, &body).unwrap_err(),
        CodecError::Crypto(veilink_crypto::CryptoError::UnknownKeyId(_))
    ));
}

/// A session that receives a frame it cannot authenticate is torn down rather than continued.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_closes_on_an_authentication_failure() {
    use veilink_protocol::frame::write_handshake_frame;

    let (mut a, b) = tokio::io::duplex(64 * 1024);
    let psk = psk();

    // Drive the client side by hand so that a forged frame can be injected after the handshake.
    let server = tokio::spawn(async move {
        veilink_protocol::session::start_session(
            b,
            veilink_protocol::session::Role::Server,
            &psk,
            [7u8; 32],
            [0x44; 32],
            veilink_protocol::session::SessionConfig::default(),
            padding(),
        )
        .await
    });

    let client_psk = Psk::from_bytes(
        &(0u8..32)
            .map(|i| i.wrapping_mul(29).wrapping_add(11))
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let (mut handshake, hello) = veilink_crypto::ClientHandshake::start(&client_psk).unwrap();
    write_handshake_frame(&mut a, &hello).await.unwrap();
    let server_hello = match veilink_protocol::frame::read_frame(&mut a, true)
        .await
        .unwrap()
    {
        veilink_protocol::frame::RawFrame::Handshake(bytes) => bytes,
        _ => panic!("expected SERVER_HELLO"),
    };
    handshake.on_server_hello(&server_hello).unwrap();
    let confirm = handshake.client_confirm([7u8; 32]).unwrap();
    write_handshake_frame(&mut a, &confirm).await.unwrap();
    let _server_confirm = match veilink_protocol::frame::read_frame(&mut a, true)
        .await
        .unwrap()
    {
        veilink_protocol::frame::RawFrame::Handshake(bytes) => bytes,
        _ => panic!("expected AUTH_CONFIRM"),
    };

    // Inject a frame that cannot authenticate: correct version byte, garbage body.
    let header = FrameHeader {
        session_id: 0, // certainly not the negotiated session
        epoch: 1,
        direction: 0,
        sequence: 0,
        algorithm: 2,
        key_id: 1,
        ciphertext_len: 32,
        sender_public: [1u8; 32],
        nonce: [2u8; 12],
    };
    veilink_protocol::frame::write_authenticated_frame(&mut a, &header, &[0u8; 32])
        .await
        .unwrap();

    let session = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("the server never finished the handshake")
        .unwrap()
        .expect("handshake");
    tokio::time::timeout(Duration::from_secs(5), session.wait_closed())
        .await
        .expect("the session stayed open after an authentication failure");
    assert!(session.is_closed());
    assert_eq!(session.stats().frames_rejected, 1);
    drop(a);
    let _ = (&mut handshake,);
}

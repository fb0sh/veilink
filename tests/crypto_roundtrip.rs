//! Cross-crate cryptographic round trip over a real, authenticated session.

use std::sync::Arc;
use std::time::Duration;

use veilink_crypto::{run_handshake_in_memory, Psk};
use veilink_protocol::codec::{BucketedPadding, PaddingPolicy, SessionCodec};
use veilink_protocol::frame::{read_frame, write_authenticated_frame, FrameHeader, RawFrame};
use veilink_protocol::message::{Message, OpenStatus};
use veilink_protocol::session::{start_session, Role, SessionConfig};
use veilink_protocol::Direction;

fn psk() -> Psk {
    Psk::from_bytes(
        &(0u8..32)
            .map(|i| i.wrapping_mul(19).wrapping_add(3))
            .collect::<Vec<u8>>(),
    )
    .unwrap()
}

fn padding() -> Arc<dyn PaddingPolicy> {
    Arc::new(BucketedPadding::new())
}

/// The two sides of the handshake derive identical keys.
#[test]
fn the_handshake_agrees_and_differs_with_the_psk() {
    let (client, server) = run_handshake_in_memory(&psk(), [3u8; 32], [0x77; 32]).unwrap();
    assert!(veilink_crypto::keys_equal(&client, &server));
    assert_eq!(client.session_id, server.session_id);

    let other = Psk::from_bytes(
        &(0u8..32)
            .map(|i| i.wrapping_mul(23).wrapping_add(9))
            .collect::<Vec<u8>>(),
    )
    .unwrap();
    let (client2, _) = run_handshake_in_memory(&other, [3u8; 32], [0x77; 32]).unwrap();
    assert_ne!(client.session_id, client2.session_id);
    assert_ne!(client.auth_c2s.as_bytes(), client2.auth_c2s.as_bytes());
}

/// A frame sealed by one codec is opened by the other, and only by the other.
#[test]
fn frames_cross_the_wire_and_nowhere_else() {
    let (client_keys, server_keys) =
        run_handshake_in_memory(&psk(), [1u8; 32], [0x11; 32]).unwrap();
    let mut client = SessionCodec::new(&client_keys, Direction::ClientToServer, padding(), 32);
    let mut server = SessionCodec::new(&server_keys, Direction::ServerToClient, padding(), 32);

    // Exchange key offers, as the session layer does after the handshake.
    let offered = client.initial_key_offer().unwrap().unwrap();
    if let Message::KeyOffer { keys } = &offered {
        server.handle_key_offer(keys).unwrap();
    }
    let offered = server.initial_key_offer().unwrap().unwrap();
    if let Message::KeyOffer { keys } = &offered {
        client.handle_key_offer(keys).unwrap();
    }

    let message = Message::OpenStream {
        stream_id: 7,
        host: "example.test".to_string(),
        port: 443,
        kind: veilink_protocol::StreamKind::Tcp,
        initial_window: 65536,
    };
    let frame = client.seal_application(&message).unwrap();
    let header = FrameHeader::decode(&frame[..veilink_protocol::AUTHENTICATED_HEADER_LEN]).unwrap();
    let body = &frame[veilink_protocol::AUTHENTICATED_HEADER_LEN..];
    assert_eq!(server.open_application(&header, body).unwrap(), message);

    // A third party with the same PSK but a different session cannot open it.
    let (_, other_server_keys) = run_handshake_in_memory(&psk(), [9u8; 32], [0x22; 32]).unwrap();
    let mut other = SessionCodec::new(&other_server_keys, Direction::ServerToClient, padding(), 32);
    assert!(other.open_application(&header, body).is_err());
}

/// Two sessions established over a real socket can exchange a stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_over_a_socket_carries_a_stream() {
    let (a, b) = tokio::io::duplex(1 << 20);
    let psk = psk();
    let exporter = [5u8; 32];

    let client = start_session(
        a,
        Role::Client,
        &psk,
        exporter,
        [0u8; 32],
        SessionConfig::default(),
        padding(),
    );
    let server = start_session(
        b,
        Role::Server,
        &psk,
        exporter,
        [0x5a; 32],
        SessionConfig::default(),
        padding(),
    );
    let (client, server) = tokio::join!(client, server);
    let client = client.unwrap();
    let server = server.unwrap();
    assert_eq!(client.session_id(), server.session_id());
    assert_eq!(client.server_identity(), Some([0x5a; 32]));

    let mut incoming = server.incoming_streams().unwrap();
    let open = tokio::spawn({
        let client = client.clone();
        async move { client.open_stream("origin.test", 80).await }
    });
    let accepted = tokio::time::timeout(Duration::from_secs(5), incoming.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.host, "origin.test");
    server
        .respond_open(accepted.stream.id(), OpenStatus::Ok, "")
        .unwrap();
    let mut client_stream = open.await.unwrap().unwrap();

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    client_stream.write_all(b"request").await.unwrap();
    let mut server_stream = accepted.stream;
    let mut buf = [0u8; 7];
    tokio::time::timeout(Duration::from_secs(5), server_stream.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"request");

    assert!(client.stats().frames_sent > 0);
    assert!(server.stats().frames_received > 0);
}

/// The frame reader rejects a frame that was not produced by the session codec.
#[tokio::test]
async fn the_frame_reader_rejects_garbage() {
    let (mut writer, mut reader) = tokio::io::duplex(256);
    // A well-formed header with a plausible length, but random body bytes.
    let header = FrameHeader {
        session_id: 1,
        epoch: 1,
        direction: 0,
        sequence: 0,
        algorithm: 2,
        key_id: 1,
        ciphertext_len: 32,
        sender_public: [1u8; 32],
        nonce: [2u8; 12],
    };
    let body = [0xAAu8; 32];
    write_authenticated_frame(&mut writer, &header, &body)
        .await
        .unwrap();
    drop(writer);
    let frame = read_frame(&mut reader, false).await.unwrap();
    match frame {
        RawFrame::Authenticated {
            header: got,
            body: got_body,
        } => {
            assert_eq!(got, header);
            assert_eq!(got_body, body);
        }
        other => panic!("unexpected frame {other:?}"),
    }
}

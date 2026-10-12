//! End-to-end `VLP/1` frame benchmarks.
//!
//! These exercise the real session codec: handshake, one-time key exchange, padding, per-frame AEAD
//! and header authentication, on both the control channel and the application channel. Nothing is
//! stubbed: every iteration goes through `SessionCodec::seal_application` /
//! `SessionCodec::open_application` exactly as the running client and server do.

use std::cell::RefCell;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use veilink_crypto::{run_handshake_in_memory, Direction, Psk};
use veilink_protocol::codec::{BucketedPadding, PaddingPolicy, SessionCodec};
use veilink_protocol::frame::{FrameHeader, AUTHENTICATED_HEADER_LEN};
use veilink_protocol::message::{Message, MAX_KEY_OFFER};

/// Size of the one-time key pool used by the frame benchmarks.
const POOL_SIZE: usize = 256;

/// A deterministic test key. The value is arbitrary and protects nothing.
fn test_psk() -> Psk {
    Psk::from_bytes(
        &(0u8..32)
            .map(|i| i.wrapping_mul(13).wrapping_add(11))
            .collect::<Vec<u8>>(),
    )
    .expect("32 distinct bytes pass the entropy sanity check")
}

/// A connected client/server codec pair with an initial exchange of one-time keys.
fn session_pair(pool_size: usize) -> (SessionCodec, SessionCodec) {
    let psk = test_psk();
    let exporter = [7u8; 32];
    let identity = [0x42u8; 32];
    let (client_keys, server_keys) =
        run_handshake_in_memory(&psk, exporter, identity).expect("the handshake must succeed");
    let padding = Arc::new(BucketedPadding::new()) as Arc<dyn PaddingPolicy>;

    let mut client = SessionCodec::new(
        &client_keys,
        Direction::ClientToServer,
        padding.clone(),
        pool_size,
    );
    let mut server = SessionCodec::new(&server_keys, Direction::ServerToClient, padding, pool_size);

    // Exchange the first batches so the client can seal application frames immediately.
    if let Some(Message::KeyOffer { keys }) = server.initial_key_offer().unwrap() {
        client.handle_key_offer(&keys).unwrap();
    }
    if let Some(Message::KeyOffer { keys }) = client.initial_key_offer().unwrap() {
        server.handle_key_offer(&keys).unwrap();
    }
    (client, server)
}

/// Publishes more receiver keys when the sender is running low.
///
/// The production path does this from the reader task, driven by the peer's traffic; a benchmark
/// has no reader task, so it is done in the (unmeasured) setup phase.
fn top_up(client: &mut SessionCodec, server: &mut SessionCodec) {
    if client.peer_keys_available() >= 8 {
        return;
    }
    let offer = match server.maybe_offer_keys().unwrap() {
        Some(offer) => Some(offer),
        // `maybe_offer_keys` is watermark-driven; fall back to an unconditional batch so that a
        // benchmark whose pool sits between the watermark and full still makes progress.
        None => server.initial_key_offer().unwrap(),
    };
    if let Some(Message::KeyOffer { keys }) = offer {
        client.handle_key_offer(&keys).unwrap();
    }
}

/// Splits a sealed frame into its header and body without copying the body.
fn split_frame(frame: &[u8]) -> (FrameHeader, &[u8]) {
    let header = FrameHeader::decode(&frame[..AUTHENTICATED_HEADER_LEN])
        .expect("a sealed frame has a header");
    (header, &frame[AUTHENTICATED_HEADER_LEN..])
}

fn frame_seal_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_frame_seal_open");
    for size in [64usize, 1024, 16 * 1024] {
        let message = Message::StreamData {
            stream_id: 1,
            data: vec![0x5au8; size],
        };
        let pair = RefCell::new(session_pair(POOL_SIZE));
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}"), |b| {
            b.iter_batched(
                || {
                    let mut pair = pair.borrow_mut();
                    let (client, server) = &mut *pair;
                    top_up(client, server);
                },
                |_| {
                    let mut pair = pair.borrow_mut();
                    // Seal and open the same message, as one request/response exchange would.
                    let frame = pair.0.seal_application(&message).unwrap();
                    let (header, body) = split_frame(&frame);
                    black_box(pair.1.open_application(&header, body).unwrap())
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn frame_seal_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_frame_seal");
    for size in [64usize, 1024, 16 * 1024] {
        let message = Message::StreamData {
            stream_id: 1,
            data: vec![0x5au8; size],
        };
        let pair = RefCell::new(session_pair(POOL_SIZE));
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}"), |b| {
            b.iter_batched(
                || {
                    let mut pair = pair.borrow_mut();
                    let (client, server) = &mut *pair;
                    top_up(client, server);
                },
                |_| {
                    let mut pair = pair.borrow_mut();
                    black_box(pair.0.seal_application(&message).unwrap().len())
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn frame_open_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_frame_open");
    for size in [64usize, 1024, 16 * 1024] {
        let message = Message::StreamData {
            stream_id: 1,
            data: vec![0x5au8; size],
        };
        let pair = RefCell::new(session_pair(POOL_SIZE));
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{size}"), |b| {
            b.iter_batched(
                || {
                    let mut pair = pair.borrow_mut();
                    let (client, server) = &mut *pair;
                    top_up(client, server);
                    client.seal_application(&message).unwrap()
                },
                |frame| {
                    let mut pair = pair.borrow_mut();
                    let (header, body) = split_frame(&frame);
                    black_box(pair.1.open_application(&header, body).unwrap())
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn control_frame(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_control_frame");
    let pair = RefCell::new(session_pair(POOL_SIZE));

    // The control channel is protected by a hash ratchet rather than a one-time key exchange, so it
    // does not need an explicit top-up.
    group.bench_function("seal_open_ping", |b| {
        b.iter_batched(
            || {
                let mut pair = pair.borrow_mut();
                pair.0
                    .seal_control(&Message::Ping { nonce: 0xabcd })
                    .unwrap()
            },
            |frame| {
                let mut pair = pair.borrow_mut();
                let (header, body) = split_frame(&frame);
                black_box(pair.1.open_control(&header, body).unwrap())
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("seal_key_offer", |b| {
        let keys: Vec<(u32, [u8; 32])> =
            (0..MAX_KEY_OFFER as u32).map(|i| (i, [0u8; 32])).collect();
        b.iter(|| {
            let mut pair = pair.borrow_mut();
            let message = Message::KeyOffer { keys: keys.clone() };
            black_box(pair.0.seal_control(&message).unwrap().len())
        })
    });

    group.finish();
}

fn message_codec(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_codec");

    group.bench_function("stream_data_encode_decode", |b| {
        let message = Message::StreamData {
            stream_id: 7,
            data: vec![0x5au8; 16 * 1024],
        };
        b.iter(|| {
            let encoded = message.encode();
            let decoded = Message::decode(&encoded).unwrap();
            black_box(decoded)
        })
    });

    group.bench_function("key_offer_encode_decode", |b| {
        let keys: Vec<(u32, [u8; 32])> =
            (0..MAX_KEY_OFFER as u32).map(|i| (i, [0u8; 32])).collect();
        let message = Message::KeyOffer { keys };
        b.iter(|| {
            let encoded = message.encode();
            let decoded = Message::decode(&encoded).unwrap();
            black_box(decoded)
        })
    });

    group.bench_function("open_stream_encode_decode", |b| {
        let message = Message::OpenStream {
            stream_id: 1,
            host: "raw.githubusercontent.com".to_string(),
            port: 443,
            kind: veilink_protocol::StreamKind::Tcp,
            initial_window: 256 * 1024,
        };
        b.iter(|| {
            let encoded = message.encode();
            let decoded = Message::decode(&encoded).unwrap();
            black_box(decoded)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    frame_seal_open,
    frame_seal_only,
    frame_open_only,
    control_frame,
    message_codec
);
criterion_main!(benches);

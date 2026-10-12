//! Privacy-mechanism benchmarks: padding policy cost and cover-traffic cost.
//!
//! These measure *cost*, not privacy. Nothing here supports a claim about detection rates; see
//! `docs/privacy.md` for what the padding and cover traffic do and do not hide.
//!
//! Three things are measured:
//!
//! * the padding policy itself (`BucketedPadding::padded_len`, `PaddingPolicy::cover_len`);
//! * the extra AEAD work that padding adds, by sealing the same message with and without it;
//! * the cost of a cover frame, which uses exactly the same per-frame cryptography as real data.

use std::cell::RefCell;
use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use veilink_crypto::{
    derive_frame_material, run_handshake_in_memory, AeadKey, AlgorithmId, Direction,
    FrameKeyContext, OneTimeKeyPair, Psk, SenderEphemeral, HASH_LEN, NONCE_LEN,
};
use veilink_protocol::codec::{BucketedPadding, PaddingPolicy, SessionCodec};
use veilink_protocol::frame::AUTHENTICATED_HEADER_LEN;
use veilink_protocol::message::Message;

/// Fixed transcript hash for the frame-key schedule.
static TRANSCRIPT_HASH: [u8; HASH_LEN] = [0x55; HASH_LEN];

/// Size of the one-time key pool used by the frame benchmarks.
const POOL_SIZE: usize = 256;

fn test_psk() -> Psk {
    Psk::from_bytes(
        &(0u8..32)
            .map(|i| i.wrapping_mul(29).wrapping_add(3))
            .collect::<Vec<u8>>(),
    )
    .expect("32 distinct bytes pass the entropy sanity check")
}

/// A prepared single frame key plus the plaintext it will encrypt.
struct Prepared {
    key: AeadKey,
    nonce: [u8; NONCE_LEN],
    aad: [u8; AUTHENTICATED_HEADER_LEN],
    plaintext: Vec<u8>,
}

/// Derives a real per-frame key and builds a plaintext of `plaintext_len` bytes.
///
/// The key comes from a genuine X25519 exchange and the real `derive_frame_material` schedule, so
/// the measured seal is the same operation the protocol performs.
fn prepare(plaintext_len: usize) -> Prepared {
    let recipient = OneTimeKeyPair::generate().unwrap();
    let public = recipient.public_key();
    let sender = SenderEphemeral::generate().unwrap();
    let sender_public = sender.public_bytes();
    let shared = sender.encapsulate(&public).unwrap();
    let context = FrameKeyContext {
        session_id: 0x0123_4567_89ab_cdef,
        epoch: 1,
        direction: Direction::ClientToServer,
        sequence: 1,
        key_id: 1,
        algorithm: AlgorithmId::ChaCha20Poly1305,
        sender_public: &sender_public,
        transcript_hash: &TRANSCRIPT_HASH,
    };
    let (key, nonce) = derive_frame_material(&shared, &context).unwrap();
    Prepared {
        key,
        nonce,
        aad: [0x33u8; AUTHENTICATED_HEADER_LEN],
        plaintext: vec![0x5au8; plaintext_len],
    }
}

fn session_pair(pool_size: usize) -> (SessionCodec, SessionCodec) {
    let psk = test_psk();
    let (client_keys, server_keys) =
        run_handshake_in_memory(&psk, [7u8; 32], [0x42u8; 32]).expect("handshake");
    let padding = Arc::new(BucketedPadding::new()) as Arc<dyn PaddingPolicy>;
    let mut client = SessionCodec::new(
        &client_keys,
        Direction::ClientToServer,
        padding.clone(),
        pool_size,
    );
    let mut server = SessionCodec::new(&server_keys, Direction::ServerToClient, padding, pool_size);
    if let Some(Message::KeyOffer { keys }) = server.initial_key_offer().unwrap() {
        client.handle_key_offer(&keys).unwrap();
    }
    if let Some(Message::KeyOffer { keys }) = client.initial_key_offer().unwrap() {
        server.handle_key_offer(&keys).unwrap();
    }
    (client, server)
}

fn top_up(client: &mut SessionCodec, server: &mut SessionCodec) {
    if client.peer_keys_available() >= 8 {
        return;
    }
    let offer = match server.maybe_offer_keys().unwrap() {
        Some(offer) => Some(offer),
        None => server.initial_key_offer().unwrap(),
    };
    if let Some(Message::KeyOffer { keys }) = offer {
        client.handle_key_offer(&keys).unwrap();
    }
}

/// The cost of the padding policy itself, across the bucket boundaries.
fn padding_policy(c: &mut Criterion) {
    let policy = BucketedPadding::new();
    let mut group = c.benchmark_group("padding_policy");

    for size in [1usize, 64, 511, 512, 1000, 4096, 8192, 20_000] {
        group.bench_with_input(format!("padded_len/{size}"), &size, |b, size| {
            b.iter(|| black_box(policy.padded_len(*size)))
        });
    }

    group.bench_function("cover_len/64..4096", |b| {
        b.iter(|| black_box(policy.cover_len(64, 4096)))
    });

    group.finish();
}

/// The extra AEAD work that padding adds for the same message.
///
/// A `STREAM_DATA` message carrying 64 bytes of payload encodes to 73 bytes. The default policy
/// rounds the plaintext (length prefix, message and random padding) up to the 512-byte bucket, so
/// the seal encrypts 512 bytes instead of 73. The two benches differ only in that rounding.
fn padding_overhead(c: &mut Criterion) {
    let policy = BucketedPadding::new();
    let message = Message::StreamData {
        stream_id: 1,
        data: vec![0u8; 64],
    }
    .encode();
    let padded_len = policy.padded_len(message.len());

    let mut group = c.benchmark_group("padding_overhead");
    group.throughput(Throughput::Bytes(message.len() as u64));
    group.bench_function("unpadded_seal", |b| {
        b.iter_batched(
            || prepare(message.len()),
            |prepared| {
                let mut buffer = prepared.plaintext;
                prepared
                    .key
                    .seal_in_place(&prepared.nonce, &prepared.aad, &mut buffer)
                    .unwrap();
                black_box(buffer.len())
            },
            BatchSize::SmallInput,
        )
    });

    group.throughput(Throughput::Bytes(padded_len as u64));
    group.bench_function("padded_seal", |b| {
        b.iter_batched(
            || {
                let mut prepared = prepare(message.len());
                // The exact plaintext layout the codec produces: u16 length, message, padding.
                prepared.plaintext.resize(padded_len, 0);
                prepared
            },
            |prepared| {
                let mut buffer = prepared.plaintext;
                prepared
                    .key
                    .seal_in_place(&prepared.nonce, &prepared.aad, &mut buffer)
                    .unwrap();
                black_box(buffer.len())
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

/// The cost of a cover frame, which is protected by the same per-frame cryptography as data.
fn cover_traffic(c: &mut Criterion) {
    let mut group = c.benchmark_group("cover_traffic_seal");
    for size in [64usize, 1024, 4096] {
        let message = Message::Cover {
            payload: vec![0u8; size],
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

criterion_group!(benches, padding_policy, padding_overhead, cover_traffic);
criterion_main!(benches);

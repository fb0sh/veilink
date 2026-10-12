//! Benchmarks for the `veilink-crypto` primitives.
//!
//! Everything here calls the real API: `AeadKey` for the three permitted AEADs, `SenderEphemeral`
//! and `OneTimeKeyPair` for the X25519 operations, and `run_handshake_in_memory` /
//! `derive_frame_material` for the key schedule. No primitive is re-implemented for measurement.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use veilink_crypto::{
    derive_frame_material, derive_handshake_keys, run_handshake_in_memory, AeadKey, AlgorithmId,
    AlgorithmSet, Direction, FrameKeyContext, OneTimeKeyPair, Psk, SenderEphemeral, Transcript,
    ALL_ALGORITHMS, HASH_LEN, NONCE_LEN,
};
use veilink_protocol::AUTHENTICATED_HEADER_LEN;

/// A fixed transcript hash for the frame-key schedule. The value is arbitrary; the schedule only
/// requires 32 bytes.
static TRANSCRIPT_HASH: [u8; HASH_LEN] = [0x55; HASH_LEN];

/// A deterministic but high-entropy test key. It protects nothing and exists for reproducibility.
fn test_psk() -> Psk {
    Psk::from_bytes(
        &(0u8..32)
            .map(|i| i.wrapping_mul(7).wrapping_add(1))
            .collect::<Vec<u8>>(),
    )
    .expect("32 distinct bytes pass the entropy sanity check")
}

/// Payload sizes used by the AEAD and frame-key groups.
const SIZES: [usize; 3] = [64, 4096, 16 * 1024];

fn aead_seal(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_seal");
    for algorithm in ALL_ALGORITHMS {
        let key = AeadKey::new(algorithm, &vec![0x11u8; algorithm.key_len()]).unwrap();
        let nonce = [0x22u8; NONCE_LEN];
        // The associated data is a real authenticated frame header: 76 bytes, all of which is
        // authenticated but none of which is encrypted.
        let aad = [0x33u8; AUTHENTICATED_HEADER_LEN];
        for size in SIZES {
            let plaintext = vec![0x5au8; size];
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(format!("{}/{size}", algorithm.name()), &size, |b, _| {
                b.iter(|| {
                    let mut buffer = plaintext.clone();
                    key.seal_in_place(&nonce, &aad, &mut buffer).unwrap();
                    black_box(buffer.len())
                })
            });
        }
    }
    group.finish();
}

fn aead_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead_open");
    for algorithm in ALL_ALGORITHMS {
        let key = AeadKey::new(algorithm, &vec![0x11u8; algorithm.key_len()]).unwrap();
        let nonce = [0x22u8; NONCE_LEN];
        let aad = [0x33u8; AUTHENTICATED_HEADER_LEN];
        for size in SIZES {
            let plaintext = vec![0x5au8; size];
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(format!("{}/{size}", algorithm.name()), &size, |b, _| {
                b.iter_batched(
                    || {
                        let mut buffer = plaintext.clone();
                        key.seal_in_place(&nonce, &aad, &mut buffer).unwrap();
                        buffer
                    },
                    |mut buffer| {
                        key.open_in_place(&nonce, &aad, &mut buffer).unwrap();
                        black_box(buffer.len())
                    },
                    BatchSize::SmallInput,
                )
            });
        }
    }
    group.finish();
}

fn x25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519");

    // A one-time receiver key pair, as published in a `KEY_OFFER`.
    group.bench_function("keygen_one_time", |b| {
        b.iter(|| black_box(OneTimeKeyPair::generate().unwrap().public_key()))
    });

    // A fresh sender ephemeral, generated once per business frame.
    group.bench_function("keygen_sender", |b| {
        b.iter(|| black_box(SenderEphemeral::generate().unwrap().public_bytes()))
    });

    // The sender side: generate + encapsulate against a published receiver key.
    let recipient = OneTimeKeyPair::generate().unwrap();
    let recipient_public = recipient.public_key();
    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            let sender = SenderEphemeral::generate().unwrap();
            black_box(
                sender
                    .encapsulate(&recipient_public)
                    .unwrap()
                    .as_bytes()
                    .to_vec(),
            )
        })
    });

    // The receiver side: generate a pair, let a sender encapsulate against it, then decapsulate.
    // Setup (generation and encapsulation) is outside the measured region.
    group.bench_function("decapsulate", |b| {
        b.iter_batched(
            || {
                let pair = OneTimeKeyPair::generate().unwrap();
                let public = pair.public_key();
                let sender = SenderEphemeral::generate().unwrap();
                let sender_public = sender.public_bytes();
                let _shared = sender.encapsulate(&public).unwrap();
                (pair, sender_public)
            },
            |(pair, sender_public)| {
                black_box(
                    pair.decapsulate(&sender_public)
                        .unwrap()
                        .as_bytes()
                        .to_vec(),
                )
            },
            BatchSize::SmallInput,
        )
    });

    // The full sender+receiver exchange, i.e. the cost of one forward-secret frame key agreement.
    group.bench_function("keygen_and_agree", |b| {
        b.iter(|| {
            let recipient = OneTimeKeyPair::generate().unwrap();
            let public = recipient.public_key();
            let sender = SenderEphemeral::generate().unwrap();
            let sender_public = sender.public_bytes();
            let sender_shared = sender.encapsulate(&public).unwrap();
            let receiver_shared = recipient.decapsulate(&sender_public).unwrap();
            black_box((
                sender_shared.as_bytes().to_vec(),
                receiver_shared.as_bytes().to_vec(),
            ))
        })
    });

    group.finish();
}

fn key_schedule(c: &mut Criterion) {
    let psk = test_psk();
    let transcript = {
        let mut transcript = Transcript::new();
        transcript.absorb(b"client-hello");
        transcript.absorb(b"server-hello");
        transcript
    };
    let hash = transcript.hash();

    let mut group = c.benchmark_group("key_schedule");

    // Deriving every session key from the PSK, the transcript and the TLS exporter.
    group.bench_function("derive_handshake_keys", |b| {
        b.iter(|| {
            let keys = derive_handshake_keys(
                &psk,
                hash,
                [0x77; HASH_LEN],
                AlgorithmSet::all(),
                AlgorithmSet::all(),
            );
            black_box(keys.session_id)
        })
    });

    // The complete in-memory handshake: two hellos, two confirmation MACs and both key sets.
    group.bench_function("handshake_full", |b| {
        b.iter(|| {
            let (client, server) =
                run_handshake_in_memory(&psk, [0x77; HASH_LEN], [0x42; 32]).unwrap();
            debug_assert_eq!(client.session_id, server.session_id);
            black_box(client.session_id)
        })
    });

    // The per-frame key schedule: X25519 shared secret plus HKDF with the full frame context.
    // Setup performs the key agreement so that only the derivation is measured.
    group.bench_function("derive_frame_material", |b| {
        b.iter_batched(
            || {
                let recipient = OneTimeKeyPair::generate().unwrap();
                let public = recipient.public_key();
                let sender = SenderEphemeral::generate().unwrap();
                let sender_public = sender.public_bytes();
                let shared = sender.encapsulate(&public).unwrap();
                (shared, sender_public)
            },
            |(shared, sender_public)| {
                let context = FrameKeyContext {
                    session_id: 0x0123_4567_89ab_cdef,
                    epoch: 1,
                    direction: Direction::ClientToServer,
                    sequence: 42,
                    key_id: 501,
                    algorithm: AlgorithmId::Aes256Gcm,
                    sender_public: &sender_public,
                    transcript_hash: &TRANSCRIPT_HASH,
                };
                let (key, nonce) = derive_frame_material(&shared, &context).unwrap();
                black_box((key.algorithm(), nonce))
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, aead_seal, aead_open, x25519, key_schedule);
criterion_main!(benches);

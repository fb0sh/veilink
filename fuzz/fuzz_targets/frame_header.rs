//! Fuzzes the authenticated frame header decoder.
//!
//! The header is cleartext and is used as associated data, so every field in it is
//! attacker-controlled. The decoder must reject anything malformed rather than trusting a length,
//! an epoch or a direction, and a header that decodes must encode back to the same bytes so that the
//! associated data a sender authenticates is exactly what a receiver reconstructs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use veilink_protocol::frame::{FrameHeader, AUTHENTICATED_HEADER_LEN, MAX_PAYLOAD};

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = FrameHeader::decode(data) {
        // The ciphertext length must never exceed what the protocol can carry in one frame,
        // including the AEAD tag; otherwise a receiver would size a buffer from an untrusted value.
        assert!(
            header.ciphertext_len as usize <= veilink_protocol::frame::MAX_CIPHERTEXT,
            "a decoded header carried an impossible ciphertext length: {}",
            header.ciphertext_len
        );
        let _ = MAX_PAYLOAD;

        // Re-encoding must reproduce the exact bytes that were authenticated.
        let reencoded = header.encode();
        let again = FrameHeader::decode(&reencoded).expect("an encoded header must decode");
        assert_eq!(again, header, "the header round trip was not stable");
        assert_eq!(reencoded.len(), AUTHENTICATED_HEADER_LEN);

        // A short slice must be rejected, never read out of bounds.
        for shorter in 0..AUTHENTICATED_HEADER_LEN {
            assert!(
                FrameHeader::decode(&reencoded[..shorter]).is_err(),
                "a truncated header of {shorter} bytes was accepted"
            );
        }

        // Flipping any single bit must either produce a different header or be rejected; it must
        // never produce the same header, which would mean a field is not covered.
        for index in 0..reencoded.len() {
            for bit in 0..8u8 {
                let mut mutated = reencoded;
                mutated[index] ^= 1 << bit;
                if let Ok(other) = FrameHeader::decode(&mutated) {
                    assert_ne!(other, header, "a bit flip at byte {index} was not observed");
                }
            }
        }
    }
});

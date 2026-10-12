//! Fuzzes the frame reader, which parses the first thing an authenticated peer sends.
//!
//! This is the highest-value target in the crate: `read_frame` consumes a two-byte version and type
//! prefix and then a length-prefixed body whose length is attacker-controlled. A missing bound on
//! that length is a remote memory-exhaustion bug, and a missing bound on the handshake frame is a
//! remote allocation bug, so the invariants below are about resource use as much as about panic
//! freedom.
//!
//! Invariants:
//!
//! * no panic, no hang and no allocation beyond the protocol's own cap for any input;
//! * a frame that parses and then re-encodes parses again to the same value.

#![no_main]

use libfuzzer_sys::fuzz_target;
use veilink_protocol::frame::{read_frame, RawFrame, MAX_HANDSHAKE_MESSAGE};

fuzz_target!(|data: &[u8]| {
    let runtime = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(runtime) => runtime,
        Err(_) => return,
    };
    let bytes = data.to_vec();
    runtime.block_on(async move {
        // Both modes are exercised: a handshake frame is accepted before authentication and is
        // therefore the more exposed of the two.
        for handshake_allowed in [true, false] {
            let mut cursor = std::io::Cursor::new(&bytes[..]);
            match read_frame(&mut cursor, handshake_allowed).await {
                Ok(RawFrame::Handshake(body)) => {
                    assert!(
                        body.len() <= MAX_HANDSHAKE_MESSAGE,
                        "a handshake frame exceeded the protocol cap: {}",
                        body.len()
                    );
                }
                Ok(RawFrame::Authenticated { header, body }) => {
                    let reencoded = header.encode();
                    let decoded = veilink_protocol::frame::FrameHeader::decode(&reencoded)
                        .expect("an encoded header must decode");
                    assert_eq!(decoded, header, "a header did not survive a round trip");
                    assert_eq!(
                        body.len(),
                        header.ciphertext_len as usize,
                        "the body length disagreed with the header"
                    );
                }
                Err(_) => {}
            }
        }
    });
});

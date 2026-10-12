//! Fuzzes the `VLP/1` message decoder.
//!
//! Every message body arrives from an untrusted peer and several variants carry length-prefixed
//! fields (host names, reasons, stream data). The decoder must never panic, never read past the end
//! of the buffer and never allocate on the strength of an unvalidated length.
//!
//! The round-trip invariant is also checked: if a message decodes, re-encoding it must produce bytes
//! that decode to the same value. A decoder that accepts two encodings of one message would make the
//! authenticated transcript ambiguous.

#![no_main]

use libfuzzer_sys::fuzz_target;
use veilink_protocol::message::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = Message::decode(data) {
        let encoded = message.encode();
        let again = Message::decode(&encoded).expect("an encoded message must decode");
        assert_eq!(again, message, "the message round trip was not stable");
        assert_eq!(
            again.encode(),
            encoded,
            "the message encoding is not canonical"
        );

        // Truncating a valid encoding must be rejected rather than silently accepted.
        for shorter in 0..encoded.len() {
            assert!(
                Message::decode(&encoded[..shorter]).is_err(),
                "a message truncated to {shorter} bytes was accepted"
            );
        }

        // Trailing bytes must not be silently ignored: the framing already carries the exact
        // length, so a leftover byte means the two sides disagree about the encoding.
        let mut extended = encoded.clone();
        extended.push(0);
        assert!(
            Message::decode(&extended).is_err(),
            "a message with a trailing byte was accepted"
        );
    }
});

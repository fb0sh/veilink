//! `VLP/1` messages: what actually travels inside a frame.
//!
//! Encoding is explicit and position-based. Every integer is big-endian and every variable-length
//! field is length-prefixed, so an implementation in another language can parse the format from the
//! table in `docs/protocol.md` without guessing. Nothing here relies on struct layout, alignment,
//! or a self-describing serialisation format.
//!
//! Messages are split into two classes, and the class determines *which keys protect the frame*:
//!
//! * **control** messages (`KEY_OFFER`, `KEY_ACK`, `PING`, `PONG`, `GOAWAY`, `ERROR`) travel on the
//!   control channel, protected by the ratcheted control key. They establish and maintain the
//!   one-time key pools, so they cannot themselves depend on a one-time key.
//! * **application** messages carry stream lifecycle and user data. They are protected by a
//!   per-frame key derived from a one-time key exchange, so the target host name, the port, the
//!   stream identifier and every byte of payload are all inside the encrypted payload.

/// The kind of stream being opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamKind {
    /// A raw TCP byte pipe: used for `CONNECT`, for plain HTTP, and for WebSocket.
    Tcp = 0,
}

impl StreamKind {
    /// Decodes a stream kind, rejecting unknown values rather than defaulting.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(StreamKind::Tcp),
            _ => None,
        }
    }
}

/// The result of an `OPEN_STREAM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpenStatus {
    /// The connection to the target is established; data may flow.
    Ok = 0,
    /// The target was refused by the server's egress policy.
    PolicyDenied = 1,
    /// The target name could not be resolved remotely.
    ResolveFailed = 2,
    /// The target refused the connection or was unreachable.
    ConnectFailed = 3,
    /// The server is at its stream limit.
    TooManyStreams = 4,
    /// The request was malformed.
    BadRequest = 5,
    /// The server is shutting down.
    ShuttingDown = 6,
    /// The target is not supported by this release (for example IPv6-only).
    Unsupported = 7,
}

impl OpenStatus {
    /// Decodes a status, returning `None` for unknown codes.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(OpenStatus::Ok),
            1 => Some(OpenStatus::PolicyDenied),
            2 => Some(OpenStatus::ResolveFailed),
            3 => Some(OpenStatus::ConnectFailed),
            4 => Some(OpenStatus::TooManyStreams),
            5 => Some(OpenStatus::BadRequest),
            6 => Some(OpenStatus::ShuttingDown),
            7 => Some(OpenStatus::Unsupported),
            _ => None,
        }
    }

    /// A short human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            OpenStatus::Ok => "ok",
            OpenStatus::PolicyDenied => "egress policy denied the target",
            OpenStatus::ResolveFailed => "remote DNS resolution failed",
            OpenStatus::ConnectFailed => "target refused the connection",
            OpenStatus::TooManyStreams => "server stream limit reached",
            OpenStatus::BadRequest => "malformed stream request",
            OpenStatus::ShuttingDown => "server is shutting down",
            OpenStatus::Unsupported => "target is not supported",
        }
    }
}

/// A `VLP/1` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    // ---- control channel ----
    /// Publishes one-time receiver public keys.
    KeyOffer {
        /// Identifier and public key for each newly published key.
        keys: Vec<(u32, [u8; 32])>,
    },
    /// Reports progress through the peer's published keys and optionally asks for more.
    KeyAck {
        /// Highest key identifier this side has consumed.
        highest_consumed: u32,
        /// Whether the peer should publish more keys.
        request_more: bool,
    },
    /// Liveness probe.
    Ping {
        /// Random value echoed back in the `PONG`.
        nonce: u64,
    },
    /// Liveness reply.
    Pong {
        /// The value from the corresponding `PING`.
        nonce: u64,
    },
    /// The sender is closing the session.
    GoAway {
        /// Reason code.
        code: u32,
        /// Human-readable reason.
        reason: String,
    },
    /// A fatal protocol error.
    Error {
        /// Error code.
        code: u32,
        /// Human-readable detail.
        message: String,
    },

    // ---- application ----
    /// Requests a new outbound stream.
    OpenStream {
        /// Stream identifier allocated by the client.
        stream_id: u32,
        /// Target host name, exactly as it should be resolved by the server.
        host: String,
        /// Target port.
        port: u16,
        /// Stream kind.
        kind: StreamKind,
        /// Bytes the client is willing to buffer for this stream.
        initial_window: u32,
    },
    /// Answers an `OPEN_STREAM`.
    OpenResult {
        /// The stream this answers.
        stream_id: u32,
        /// Outcome.
        status: OpenStatus,
        /// Optional detail, empty when the status is `Ok`.
        detail: String,
        /// Bytes the server is willing to buffer for this stream (only meaningful for `Ok`).
        initial_window: u32,
    },
    /// Carries stream payload.
    StreamData {
        /// The stream this data belongs to.
        stream_id: u32,
        /// Payload bytes.
        data: Vec<u8>,
    },
    /// Grants the peer more send credit on a stream.
    StreamWindow {
        /// The stream receiving credit.
        stream_id: u32,
        /// Additional bytes the peer may send.
        credit: u32,
    },
    /// Half-closes a stream: no more data will be sent in this direction.
    StreamFin {
        /// The stream to half-close.
        stream_id: u32,
    },
    /// Aborts a stream in both directions.
    StreamReset {
        /// The stream to abort.
        stream_id: u32,
        /// Reason code.
        code: u32,
        /// Human-readable reason.
        reason: String,
    },
    /// Cover traffic: authenticated padding that the receiver discards.
    Cover {
        /// Random bytes.
        payload: Vec<u8>,
    },
}

/// Message type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// `KEY_OFFER`.
    KeyOffer = 0x10,
    /// `KEY_ACK`.
    KeyAck = 0x11,
    /// `OPEN_STREAM`.
    OpenStream = 0x20,
    /// `OPEN_RESULT`.
    OpenResult = 0x21,
    /// `STREAM_DATA`.
    StreamData = 0x22,
    /// `STREAM_FIN`.
    StreamFin = 0x23,
    /// `STREAM_RESET`.
    StreamReset = 0x24,
    /// `STREAM_WINDOW`.
    StreamWindow = 0x25,
    /// `PING`.
    Ping = 0x30,
    /// `PONG`.
    Pong = 0x31,
    /// `COVER_DATA`.
    Cover = 0x32,
    /// `GOAWAY`.
    GoAway = 0x40,
    /// `ERROR`.
    Error = 0x7f,
}

/// Maximum length of a host name carried in `OPEN_STREAM`.
pub const MAX_HOST_LEN: usize = 255;
/// Maximum length of a detail or reason string.
pub const MAX_TEXT_LEN: usize = 256;
/// Maximum number of keys in one `KEY_OFFER`.
pub const MAX_KEY_OFFER: usize = veilink_crypto::MAX_OFFER_BATCH;

/// Errors raised while encoding or decoding a message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MessageError {
    /// The buffer ended before the message did.
    #[error("message is truncated: needed {needed} bytes, found {actual}")]
    Truncated {
        /// Required length.
        needed: usize,
        /// Available length.
        actual: usize,
    },
    /// The type byte was not recognised.
    #[error("unknown message type 0x{0:02x}")]
    UnknownType(u8),
    /// A message was empty.
    #[error("empty message")]
    Empty,
    /// A length-prefixed field exceeded its bound.
    #[error("{field} of {length} bytes exceeds the {limit} byte limit")]
    FieldTooLong {
        /// Which field.
        field: &'static str,
        /// Observed length.
        length: usize,
        /// Permitted length.
        limit: usize,
    },
    /// A string field was not valid UTF-8.
    #[error("{field} is not valid UTF-8")]
    BadUtf8 {
        /// Which field.
        field: &'static str,
    },
    /// A field carried an out-of-range or unknown value.
    #[error("{field} has an invalid value: {detail}")]
    Invalid {
        /// Which field.
        field: &'static str,
        /// What was wrong.
        detail: String,
    },
    /// Bytes remained after decoding.
    #[error("{0} trailing bytes after the message")]
    Trailing(usize),
}

/// A minimal big-endian writer.
struct Encoder {
    out: Vec<u8>,
}

impl Encoder {
    fn new(capacity: usize) -> Self {
        Encoder {
            out: Vec::with_capacity(capacity),
        }
    }

    fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.out.extend_from_slice(value);
    }

    fn text(&mut self, value: &str, limit: usize) -> usize {
        let bytes = value.as_bytes();
        let take = bytes.len().min(limit);
        self.u16(take as u16);
        self.bytes(&bytes[..take]);
        take
    }
}

/// A minimal big-endian reader with bounds checking.
struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Decoder { input, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.position)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], MessageError> {
        if self.remaining() < count {
            return Err(MessageError::Truncated {
                needed: count,
                actual: self.remaining(),
            });
        }
        let slice = &self.input[self.position..self.position + count];
        self.position += count;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, MessageError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, MessageError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, MessageError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, MessageError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().expect("8 bytes")))
    }

    fn array32(&mut self) -> Result<[u8; 32], MessageError> {
        let bytes = self.take(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn text(&mut self, field: &'static str, limit: usize) -> Result<String, MessageError> {
        let length = self.u16()? as usize;
        if length > limit {
            return Err(MessageError::FieldTooLong {
                field,
                length,
                limit,
            });
        }
        let bytes = self.take(length)?;
        std::str::from_utf8(bytes)
            .map(|s| s.to_string())
            .map_err(|_| MessageError::BadUtf8 { field })
    }

    fn finish(self) -> Result<(), MessageError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(MessageError::Trailing(self.remaining()))
        }
    }
}

impl Message {
    /// True when this message travels on the control channel.
    pub fn is_control(&self) -> bool {
        matches!(
            self,
            Message::KeyOffer { .. }
                | Message::KeyAck { .. }
                | Message::Ping { .. }
                | Message::Pong { .. }
                | Message::GoAway { .. }
                | Message::Error { .. }
        )
    }

    /// The stream this message concerns, when it concerns one.
    pub fn stream_id(&self) -> Option<u32> {
        match self {
            Message::OpenStream { stream_id, .. }
            | Message::OpenResult { stream_id, .. }
            | Message::StreamData { stream_id, .. }
            | Message::StreamWindow { stream_id, .. }
            | Message::StreamFin { stream_id }
            | Message::StreamReset { stream_id, .. } => Some(*stream_id),
            _ => None,
        }
    }

    /// The message type identifier.
    pub fn message_type(&self) -> MessageType {
        match self {
            Message::KeyOffer { .. } => MessageType::KeyOffer,
            Message::KeyAck { .. } => MessageType::KeyAck,
            Message::OpenStream { .. } => MessageType::OpenStream,
            Message::OpenResult { .. } => MessageType::OpenResult,
            Message::StreamData { .. } => MessageType::StreamData,
            Message::StreamFin { .. } => MessageType::StreamFin,
            Message::StreamReset { .. } => MessageType::StreamReset,
            Message::StreamWindow { .. } => MessageType::StreamWindow,
            Message::Ping { .. } => MessageType::Ping,
            Message::Pong { .. } => MessageType::Pong,
            Message::Cover { .. } => MessageType::Cover,
            Message::GoAway { .. } => MessageType::GoAway,
            Message::Error { .. } => MessageType::Error,
        }
    }

    /// Encodes the message.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new(64);
        encoder.u8(self.message_type() as u8);
        match self {
            Message::KeyOffer { keys } => {
                encoder.u16(keys.len() as u16);
                for (id, public) in keys {
                    encoder.u32(*id);
                    encoder.bytes(public);
                }
            }
            Message::KeyAck {
                highest_consumed,
                request_more,
            } => {
                encoder.u32(*highest_consumed);
                encoder.u8(u8::from(*request_more));
            }
            Message::Ping { nonce } | Message::Pong { nonce } => encoder.u64(*nonce),
            Message::GoAway { code, reason }
            | Message::Error {
                code,
                message: reason,
            } => {
                encoder.u32(*code);
                encoder.text(reason, MAX_TEXT_LEN);
            }
            Message::OpenStream {
                stream_id,
                host,
                port,
                kind,
                initial_window,
            } => {
                encoder.u32(*stream_id);
                encoder.u8(*kind as u8);
                encoder.u16(*port);
                encoder.u32(*initial_window);
                encoder.text(host, MAX_HOST_LEN);
            }
            Message::OpenResult {
                stream_id,
                status,
                detail,
                initial_window,
            } => {
                encoder.u32(*stream_id);
                encoder.u8(*status as u8);
                encoder.u32(*initial_window);
                encoder.text(detail, MAX_TEXT_LEN);
            }
            Message::StreamData { stream_id, data } => {
                encoder.u32(*stream_id);
                encoder.u32(data.len() as u32);
                encoder.bytes(data);
            }
            Message::StreamWindow { stream_id, credit } => {
                encoder.u32(*stream_id);
                encoder.u32(*credit);
            }
            Message::StreamFin { stream_id } => encoder.u32(*stream_id),
            Message::StreamReset {
                stream_id,
                code,
                reason,
            } => {
                encoder.u32(*stream_id);
                encoder.u32(*code);
                encoder.text(reason, MAX_TEXT_LEN);
            }
            Message::Cover { payload } => {
                encoder.u32(payload.len() as u32);
                encoder.bytes(payload);
            }
        }
        encoder.out
    }

    /// Decodes a message.
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        let mut decoder = Decoder::new(bytes);
        let kind = decoder.u8().map_err(|_| MessageError::Empty)?;
        let message = match kind {
            0x10 => {
                let count = decoder.u16()? as usize;
                if count > MAX_KEY_OFFER {
                    return Err(MessageError::FieldTooLong {
                        field: "key count",
                        length: count,
                        limit: MAX_KEY_OFFER,
                    });
                }
                let mut keys = Vec::with_capacity(count);
                for _ in 0..count {
                    let id = decoder.u32()?;
                    let public = decoder.array32()?;
                    keys.push((id, public));
                }
                Message::KeyOffer { keys }
            }
            0x11 => {
                let highest_consumed = decoder.u32()?;
                let request_more = decoder.u8()? != 0;
                Message::KeyAck {
                    highest_consumed,
                    request_more,
                }
            }
            0x20 => {
                let stream_id = decoder.u32()?;
                let kind_raw = decoder.u8()?;
                let kind = StreamKind::from_u8(kind_raw).ok_or(MessageError::Invalid {
                    field: "stream kind",
                    detail: format!("{kind_raw}"),
                })?;
                let port = decoder.u16()?;
                if port == 0 {
                    return Err(MessageError::Invalid {
                        field: "port",
                        detail: "port 0 is not a valid destination".to_string(),
                    });
                }
                let initial_window = decoder.u32()?;
                let host = decoder.text("host", MAX_HOST_LEN)?;
                if host.is_empty() {
                    return Err(MessageError::Invalid {
                        field: "host",
                        detail: "host must not be empty".to_string(),
                    });
                }
                Message::OpenStream {
                    stream_id,
                    host,
                    port,
                    kind,
                    initial_window,
                }
            }
            0x21 => {
                let stream_id = decoder.u32()?;
                let status_raw = decoder.u8()?;
                let status = OpenStatus::from_u8(status_raw).ok_or(MessageError::Invalid {
                    field: "open status",
                    detail: format!("{status_raw}"),
                })?;
                let initial_window = decoder.u32()?;
                let detail = decoder.text("detail", MAX_TEXT_LEN)?;
                Message::OpenResult {
                    stream_id,
                    status,
                    detail,
                    initial_window,
                }
            }
            0x22 => {
                let stream_id = decoder.u32()?;
                let length = decoder.u32()? as usize;
                if length > crate::frame::MAX_PAYLOAD {
                    return Err(MessageError::FieldTooLong {
                        field: "stream data",
                        length,
                        limit: crate::frame::MAX_PAYLOAD,
                    });
                }
                let data = decoder.take(length)?.to_vec();
                Message::StreamData { stream_id, data }
            }
            0x25 => {
                let stream_id = decoder.u32()?;
                let credit = decoder.u32()?;
                Message::StreamWindow { stream_id, credit }
            }
            0x23 => Message::StreamFin {
                stream_id: decoder.u32()?,
            },
            0x24 => {
                let stream_id = decoder.u32()?;
                let code = decoder.u32()?;
                let reason = decoder.text("reason", MAX_TEXT_LEN)?;
                Message::StreamReset {
                    stream_id,
                    code,
                    reason,
                }
            }
            0x30 => Message::Ping {
                nonce: decoder.u64()?,
            },
            0x31 => Message::Pong {
                nonce: decoder.u64()?,
            },
            0x32 => {
                let length = decoder.u32()? as usize;
                if length > crate::frame::MAX_PAYLOAD {
                    return Err(MessageError::FieldTooLong {
                        field: "cover data",
                        length,
                        limit: crate::frame::MAX_PAYLOAD,
                    });
                }
                Message::Cover {
                    payload: decoder.take(length)?.to_vec(),
                }
            }
            0x40 => {
                let code = decoder.u32()?;
                let reason = decoder.text("reason", MAX_TEXT_LEN)?;
                Message::GoAway { code, reason }
            }
            0x7f => {
                let code = decoder.u32()?;
                let message = decoder.text("message", MAX_TEXT_LEN)?;
                Message::Error { code, message }
            }
            other => return Err(MessageError::UnknownType(other)),
        };
        decoder.finish()?;
        Ok(message)
    }
}

/// The header overhead of a `STREAM_DATA` message, used when fragmenting payloads.
pub const STREAM_DATA_OVERHEAD: usize = 1 + 4 + 4;

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(message: Message) {
        let encoded = message.encode();
        let decoded = Message::decode(&encoded).expect("decode");
        assert_eq!(decoded, message, "round trip changed the message");
    }

    #[test]
    fn every_message_round_trips() {
        round_trip(Message::KeyOffer {
            keys: vec![(1, [0xAA; 32]), (2, [0xBB; 32])],
        });
        round_trip(Message::KeyAck {
            highest_consumed: 99,
            request_more: true,
        });
        round_trip(Message::Ping { nonce: 0x1234 });
        round_trip(Message::Pong { nonce: 0x1234 });
        round_trip(Message::GoAway {
            code: 1,
            reason: "shutting down".into(),
        });
        round_trip(Message::Error {
            code: 7,
            message: "bad frame".into(),
        });
        round_trip(Message::OpenStream {
            stream_id: 5,
            host: "github.com".into(),
            port: 443,
            kind: StreamKind::Tcp,
            initial_window: 256 * 1024,
        });
        round_trip(Message::OpenResult {
            stream_id: 5,
            status: OpenStatus::Ok,
            detail: String::new(),
            initial_window: 256 * 1024,
        });
        round_trip(Message::StreamData {
            stream_id: 5,
            data: vec![1, 2, 3],
        });
        round_trip(Message::StreamWindow {
            stream_id: 5,
            credit: 4096,
        });
        round_trip(Message::StreamFin { stream_id: 5 });
        round_trip(Message::StreamReset {
            stream_id: 5,
            code: 2,
            reason: "cancelled".into(),
        });
        round_trip(Message::Cover {
            payload: vec![0u8; 512],
        });
        round_trip(Message::StreamData {
            stream_id: 5,
            data: Vec::new(),
        });
    }

    #[test]
    fn control_and_application_classes_are_distinct() {
        assert!(Message::Ping { nonce: 1 }.is_control());
        assert!(Message::KeyAck {
            highest_consumed: 0,
            request_more: false
        }
        .is_control());
        assert!(!Message::OpenStream {
            stream_id: 1,
            host: "a".into(),
            port: 1,
            kind: StreamKind::Tcp,
            initial_window: 1
        }
        .is_control());
        assert!(!Message::StreamData {
            stream_id: 1,
            data: vec![]
        }
        .is_control());
        assert!(!Message::Cover { payload: vec![] }.is_control());
    }

    #[test]
    fn stream_ids_are_reported() {
        assert_eq!(Message::StreamFin { stream_id: 9 }.stream_id(), Some(9));
        assert_eq!(Message::Ping { nonce: 0 }.stream_id(), None);
    }

    #[test]
    fn unknown_types_and_empty_input_are_rejected() {
        assert_eq!(Message::decode(&[]).unwrap_err(), MessageError::Empty);
        assert_eq!(
            Message::decode(&[0x99]).unwrap_err(),
            MessageError::UnknownType(0x99)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = Message::StreamFin { stream_id: 1 }.encode();
        encoded.push(0);
        assert!(matches!(
            Message::decode(&encoded).unwrap_err(),
            MessageError::Trailing(1)
        ));
    }

    #[test]
    fn truncated_messages_are_rejected() {
        let encoded = Message::OpenStream {
            stream_id: 1,
            host: "example.com".into(),
            port: 443,
            kind: StreamKind::Tcp,
            initial_window: 1,
        }
        .encode();
        for cut in 1..encoded.len() {
            assert!(
                Message::decode(&encoded[..cut]).is_err(),
                "a message truncated to {cut} bytes was accepted"
            );
        }
    }

    #[test]
    fn invalid_field_values_are_rejected() {
        // Port 0.
        let mut encoded = Message::OpenStream {
            stream_id: 1,
            host: "a".into(),
            port: 443,
            kind: StreamKind::Tcp,
            initial_window: 1,
        }
        .encode();
        // type(1) stream(4) kind(1) port(2)
        encoded[6] = 0;
        encoded[7] = 0;
        assert!(matches!(
            Message::decode(&encoded).unwrap_err(),
            MessageError::Invalid { field: "port", .. }
        ));

        // Unknown stream kind.
        let mut encoded = Message::OpenStream {
            stream_id: 1,
            host: "a".into(),
            port: 443,
            kind: StreamKind::Tcp,
            initial_window: 1,
        }
        .encode();
        encoded[5] = 9;
        assert!(matches!(
            Message::decode(&encoded).unwrap_err(),
            MessageError::Invalid {
                field: "stream kind",
                ..
            }
        ));

        // Unknown open status.
        let mut encoded = Message::OpenResult {
            stream_id: 1,
            status: OpenStatus::Ok,
            detail: String::new(),
            initial_window: 1,
        }
        .encode();
        encoded[5] = 99;
        assert!(Message::decode(&encoded).is_err());
    }

    #[test]
    fn oversized_fields_are_rejected_without_allocating() {
        // An `OPEN_STREAM` that claims a 60000-byte host name.
        let mut encoded = vec![0x20];
        encoded.extend_from_slice(&1u32.to_be_bytes());
        encoded.push(0);
        encoded.extend_from_slice(&443u16.to_be_bytes());
        encoded.extend_from_slice(&1024u32.to_be_bytes());
        encoded.extend_from_slice(&60000u16.to_be_bytes());
        encoded.extend_from_slice(&[b'a'; 8]);
        assert!(matches!(
            Message::decode(&encoded).unwrap_err(),
            MessageError::FieldTooLong {
                field: "host",
                limit: MAX_HOST_LEN,
                ..
            }
        ));

        // A `KEY_OFFER` claiming more keys than the protocol allows.
        let mut encoded = vec![0x10];
        encoded.extend_from_slice(&60000u16.to_be_bytes());
        assert!(matches!(
            Message::decode(&encoded).unwrap_err(),
            MessageError::FieldTooLong {
                field: "key count",
                ..
            }
        ));

        // `STREAM_DATA` claiming 4 GiB.
        let mut encoded = vec![0x22];
        encoded.extend_from_slice(&1u32.to_be_bytes());
        encoded.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            Message::decode(&encoded).unwrap_err(),
            MessageError::FieldTooLong {
                field: "stream data",
                ..
            }
        ));
    }

    #[test]
    fn non_utf8_text_is_rejected() {
        let mut encoded = vec![0x40];
        encoded.extend_from_slice(&1u32.to_be_bytes());
        encoded.extend_from_slice(&2u16.to_be_bytes());
        encoded.extend_from_slice(&[0xff, 0xfe]);
        assert!(matches!(
            Message::decode(&encoded).unwrap_err(),
            MessageError::BadUtf8 { field: "reason" }
        ));
    }

    #[test]
    fn long_reason_strings_are_truncated_on_encode() {
        let long = "x".repeat(MAX_TEXT_LEN * 4);
        let encoded = Message::GoAway {
            code: 1,
            reason: long,
        }
        .encode();
        let decoded = Message::decode(&encoded).unwrap();
        match decoded {
            Message::GoAway { reason, .. } => assert_eq!(reason.len(), MAX_TEXT_LEN),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn large_key_offers_are_bounded() {
        let keys: Vec<(u32, [u8; 32])> =
            (0..MAX_KEY_OFFER as u32).map(|i| (i, [0u8; 32])).collect();
        let encoded = Message::KeyOffer { keys: keys.clone() }.encode();
        assert_eq!(
            Message::decode(&encoded).unwrap(),
            Message::KeyOffer { keys }
        );
    }

    #[test]
    fn open_status_names_are_stable() {
        for status in [
            OpenStatus::Ok,
            OpenStatus::PolicyDenied,
            OpenStatus::ResolveFailed,
            OpenStatus::ConnectFailed,
            OpenStatus::TooManyStreams,
            OpenStatus::BadRequest,
            OpenStatus::ShuttingDown,
            OpenStatus::Unsupported,
        ] {
            assert!(!status.name().is_empty());
            assert_eq!(OpenStatus::from_u8(status as u8).unwrap(), status);
        }
    }
}

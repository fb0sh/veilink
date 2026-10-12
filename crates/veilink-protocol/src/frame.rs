//! The `VLP/1` wire frame.
//!
//! # Layout
//!
//! Every frame begins with two bytes that are always visible on the wire:
//!
//! ```text
//! offset size field
//! 0      1    frame version (0x56, 'V')
//! 1      1    frame type: 0 = handshake (cleartext), 1 = authenticated
//! ```
//!
//! A **handshake** frame carries a cleartext, length-prefixed message and is only legal before the
//! handshake has completed:
//!
//! ```text
//! 2      2    message length
//! 4      N    message bytes
//! ```
//!
//! An **authenticated** frame has a 76-byte header that is transmitted in the clear but is
//! cryptographically authenticated as the AEAD associated data:
//!
//! ```text
//! offset size field
//! 0      1    frame version
//! 1      1    frame type = 1
//! 2      8    session id          (u64, big endian)
//! 10     4    epoch               (u32, big endian)
//! 14     1    direction: 0 = client to server, 1 = server to client
//! 15     8    sequence            (u64, big endian)
//! 23     1    algorithm id
//! 24     4    key id              (u32, big endian; 0 for control frames)
//! 28     4    ciphertext length   (u32, big endian, includes the 16-byte tag)
//! 32     32   sender ephemeral X25519 public key (all zeroes for control frames)
//! 64     12   nonce
//! 76     N    ciphertext || tag
//! ```
//!
//! # What is visible, and what that costs
//!
//! A passive observer sees: that Veilink is in use, the frame type byte, a per-session random
//! identifier, a direction bit, a monotonically increasing sequence number, an algorithm
//! identifier, the record length and timing. That is a real metadata leak and it is discussed
//! honestly in `docs/privacy.md`.
//!
//! What the observer does **not** see: the target host name, the target port, the stream
//! identifier, the request method, any header, any body byte, and whether a frame carries real
//! traffic or cover traffic. Those all live inside the encrypted payload.
//!
//! # Bounds
//!
//! A receiver never trusts the length field. A frame is rejected unless
//! `ciphertext_len` is within `[16, MAX_CIPHERTEXT]`, and the reader allocates from the validated
//! value only. This bounds memory to a constant per connection regardless of what a peer claims.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// First byte of every `VLP/1` frame.
pub const FRAME_VERSION: u8 = 0x56;

/// A cleartext handshake message.
pub const FRAME_TYPE_HANDSHAKE: u8 = 0;
/// An authenticated frame protected by an AEAD.
pub const FRAME_TYPE_AUTHENTICATED: u8 = 1;

/// Length of the authenticated frame header.
pub const AUTHENTICATED_HEADER_LEN: usize = 76;

/// Largest plaintext payload accepted inside one authenticated frame.
pub const MAX_PAYLOAD: usize = 64 * 1024;

/// Maximum padding added on top of a payload before sealing.
pub const MAX_PADDING: usize = 4096;

/// Largest ciphertext accepted, tag included.
pub const MAX_CIPHERTEXT: usize = MAX_PAYLOAD + MAX_PADDING + 16;

/// Largest cleartext handshake message accepted.
pub const MAX_HANDSHAKE_MESSAGE: usize = 8 * 1024;

/// A parsed authenticated frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Session identifier.
    pub session_id: u64,
    /// Key generation.
    pub epoch: u32,
    /// Direction of travel.
    pub direction: u8,
    /// Frame sequence number.
    pub sequence: u64,
    /// AEAD algorithm identifier.
    pub algorithm: u8,
    /// Identifier of the recipient's one-time key. Zero for control frames.
    pub key_id: u32,
    /// Length of the ciphertext, tag included.
    pub ciphertext_len: u32,
    /// The sender's fresh ephemeral public key.
    pub sender_public: [u8; 32],
    /// The AEAD nonce.
    pub nonce: [u8; 12],
}

impl FrameHeader {
    /// Encodes the header. The result is also the AEAD associated data.
    pub fn encode(&self) -> [u8; AUTHENTICATED_HEADER_LEN] {
        let mut out = [0u8; AUTHENTICATED_HEADER_LEN];
        out[0] = FRAME_VERSION;
        out[1] = FRAME_TYPE_AUTHENTICATED;
        out[2..10].copy_from_slice(&self.session_id.to_be_bytes());
        out[10..14].copy_from_slice(&self.epoch.to_be_bytes());
        out[14] = self.direction;
        out[15..23].copy_from_slice(&self.sequence.to_be_bytes());
        out[23] = self.algorithm;
        out[24..28].copy_from_slice(&self.key_id.to_be_bytes());
        out[28..32].copy_from_slice(&self.ciphertext_len.to_be_bytes());
        out[32..64].copy_from_slice(&self.sender_public);
        out[64..76].copy_from_slice(&self.nonce);
        out
    }

    /// Decodes a header from exactly [`AUTHENTICATED_HEADER_LEN`] bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < AUTHENTICATED_HEADER_LEN {
            return Err(FrameError::TruncatedHeader);
        }
        if bytes[0] != FRAME_VERSION {
            return Err(FrameError::BadVersion(bytes[0]));
        }
        if bytes[1] != FRAME_TYPE_AUTHENTICATED {
            return Err(FrameError::BadFrameType(bytes[1]));
        }
        let session_id = u64::from_be_bytes(bytes[2..10].try_into().expect("8 bytes"));
        let epoch = u32::from_be_bytes(bytes[10..14].try_into().expect("4 bytes"));
        let direction = bytes[14];
        if direction > 1 {
            return Err(FrameError::BadDirection(direction));
        }
        let sequence = u64::from_be_bytes(bytes[15..23].try_into().expect("8 bytes"));
        let algorithm = bytes[23];
        let key_id = u32::from_be_bytes(bytes[24..28].try_into().expect("4 bytes"));
        let ciphertext_len = u32::from_be_bytes(bytes[28..32].try_into().expect("4 bytes"));
        let mut sender_public = [0u8; 32];
        sender_public.copy_from_slice(&bytes[32..64]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes[64..76]);

        if ciphertext_len < 16 {
            return Err(FrameError::LengthOutOfRange(ciphertext_len));
        }
        if ciphertext_len as usize > MAX_CIPHERTEXT {
            return Err(FrameError::LengthOutOfRange(ciphertext_len));
        }

        Ok(FrameHeader {
            session_id,
            epoch,
            direction,
            sequence,
            algorithm,
            key_id,
            ciphertext_len,
            sender_public,
            nonce,
        })
    }

    /// The AEAD associated data: the encoded header itself.
    pub fn associated_data(&self) -> [u8; AUTHENTICATED_HEADER_LEN] {
        self.encode()
    }

    /// Total on-wire size of the frame this header describes.
    pub fn total_len(&self) -> usize {
        AUTHENTICATED_HEADER_LEN + self.ciphertext_len as usize
    }
}

/// A frame read from the wire.
#[derive(Debug, Clone)]
pub enum RawFrame {
    /// A cleartext handshake message.
    Handshake(Vec<u8>),
    /// An authenticated frame: header plus `ciphertext || tag`.
    Authenticated {
        /// The authenticated header.
        header: FrameHeader,
        /// The ciphertext, tag included.
        body: Vec<u8>,
    },
}

impl RawFrame {
    /// Total on-wire size of the frame.
    pub fn wire_len(&self) -> usize {
        match self {
            // Two type bytes plus a two-byte length prefix.
            RawFrame::Handshake(message) => 4 + message.len(),
            RawFrame::Authenticated { header: _, body } => AUTHENTICATED_HEADER_LEN + body.len(),
        }
    }
}

/// Frame-level errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The frame version byte was not `VLP/1`.
    #[error("unsupported frame version 0x{0:02x}")]
    BadVersion(u8),
    /// The frame type byte was not recognised.
    #[error("unsupported frame type {0}")]
    BadFrameType(u8),
    /// The direction byte was not 0 or 1.
    #[error("invalid frame direction {0}")]
    BadDirection(u8),
    /// The declared length was outside the permitted range.
    #[error("declared frame length {0} is outside the permitted range")]
    LengthOutOfRange(u32),
    /// The header was incomplete.
    #[error("truncated frame header")]
    TruncatedHeader,
    /// A cleartext handshake message was too large.
    #[error("handshake message of {0} bytes exceeds the maximum")]
    HandshakeTooLarge(usize),
    /// A cleartext handshake frame arrived after the handshake completed.
    #[error("cleartext handshake frame received on an established session")]
    CleartextAfterHandshake,
}

impl From<FrameError> for io::Error {
    fn from(value: FrameError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, value.to_string())
    }
}

/// Writes a cleartext handshake frame.
pub async fn write_handshake_frame<W>(writer: &mut W, message: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if message.len() > MAX_HANDSHAKE_MESSAGE {
        return Err(FrameError::HandshakeTooLarge(message.len()).into());
    }
    let mut out = Vec::with_capacity(4 + message.len());
    out.push(FRAME_VERSION);
    out.push(FRAME_TYPE_HANDSHAKE);
    out.extend_from_slice(&(message.len() as u16).to_be_bytes());
    out.extend_from_slice(message);
    writer.write_all(&out).await?;
    writer.flush().await
}

/// Writes an authenticated frame from a prepared header and body.
pub async fn write_authenticated_frame<W>(
    writer: &mut W,
    header: &FrameHeader,
    body: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if body.len() != header.ciphertext_len as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame body length does not match the declared ciphertext length",
        ));
    }
    let mut out = Vec::with_capacity(AUTHENTICATED_HEADER_LEN + body.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(body);
    writer.write_all(&out).await?;
    writer.flush().await
}

/// Reads one frame of either kind.
///
/// `handshake_allowed` must be `false` once the session is established; a cleartext frame arriving
/// afterwards is rejected rather than interpreted.
pub async fn read_frame<R>(reader: &mut R, handshake_allowed: bool) -> io::Result<RawFrame>
where
    R: AsyncRead + Unpin,
{
    let mut prefix = [0u8; 2];
    reader.read_exact(&mut prefix).await?;
    if prefix[0] != FRAME_VERSION {
        return Err(FrameError::BadVersion(prefix[0]).into());
    }
    match prefix[1] {
        FRAME_TYPE_HANDSHAKE => {
            if !handshake_allowed {
                return Err(FrameError::CleartextAfterHandshake.into());
            }
            let mut length = [0u8; 2];
            reader.read_exact(&mut length).await?;
            let length = u16::from_be_bytes(length) as usize;
            if length > MAX_HANDSHAKE_MESSAGE {
                return Err(FrameError::HandshakeTooLarge(length).into());
            }
            let mut message = vec![0u8; length];
            reader.read_exact(&mut message).await?;
            Ok(RawFrame::Handshake(message))
        }
        FRAME_TYPE_AUTHENTICATED => {
            let mut rest = [0u8; AUTHENTICATED_HEADER_LEN - 2];
            reader.read_exact(&mut rest).await?;
            let mut header_bytes = [0u8; AUTHENTICATED_HEADER_LEN];
            header_bytes[..2].copy_from_slice(&prefix);
            header_bytes[2..].copy_from_slice(&rest);
            let header = FrameHeader::decode(&header_bytes)?;
            // The length was validated before allocating.
            let mut body = vec![0u8; header.ciphertext_len as usize];
            reader.read_exact(&mut body).await?;
            Ok(RawFrame::Authenticated { header, body })
        }
        other => Err(FrameError::BadFrameType(other).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> FrameHeader {
        FrameHeader {
            session_id: 0x0123_4567_89ab_cdef,
            epoch: 7,
            direction: 1,
            sequence: 0xdead_beef_cafe,
            algorithm: 2,
            key_id: 4242,
            ciphertext_len: 32,
            sender_public: [0x11; 32],
            nonce: [0x22; 12],
        }
    }

    #[test]
    fn header_round_trips() {
        let header = sample_header();
        let bytes = header.encode();
        assert_eq!(bytes.len(), AUTHENTICATED_HEADER_LEN);
        assert_eq!(bytes[0], FRAME_VERSION);
        assert_eq!(bytes[1], FRAME_TYPE_AUTHENTICATED);
        assert_eq!(FrameHeader::decode(&bytes).unwrap(), header);
        assert_eq!(header.total_len(), AUTHENTICATED_HEADER_LEN + 32);
    }

    #[test]
    fn header_rejects_bad_fields() {
        let header = sample_header();

        let mut bytes = header.encode();
        bytes[0] = 0x00;
        assert_eq!(
            FrameHeader::decode(&bytes).unwrap_err(),
            FrameError::BadVersion(0)
        );

        let mut bytes = header.encode();
        bytes[1] = 9;
        assert_eq!(
            FrameHeader::decode(&bytes).unwrap_err(),
            FrameError::BadFrameType(9)
        );

        let mut bytes = header.encode();
        bytes[14] = 2;
        assert_eq!(
            FrameHeader::decode(&bytes).unwrap_err(),
            FrameError::BadDirection(2)
        );

        // Lengths below the tag size and above the maximum are both refused.
        let mut bytes = header.encode();
        bytes[28..32].copy_from_slice(&15u32.to_be_bytes());
        assert!(matches!(
            FrameHeader::decode(&bytes),
            Err(FrameError::LengthOutOfRange(15))
        ));

        let mut bytes = header.encode();
        bytes[28..32].copy_from_slice(&(MAX_CIPHERTEXT as u32 + 1).to_be_bytes());
        assert!(matches!(
            FrameHeader::decode(&bytes),
            Err(FrameError::LengthOutOfRange(_))
        ));

        // A truncated header is refused rather than over-read.
        assert_eq!(
            FrameHeader::decode(&header.encode()[..40]).unwrap_err(),
            FrameError::TruncatedHeader
        );
    }

    #[test]
    fn oversized_declared_length_is_rejected_before_allocating() {
        // 0xffff_ffff would be a 4 GiB allocation if the field were trusted.
        let header = sample_header();
        let mut bytes = header.encode();
        bytes[28..32].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(FrameHeader::decode(&bytes).is_err());
    }

    #[tokio::test]
    async fn handshake_frames_round_trip() {
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let message = b"CLIENT_HELLO-ish".to_vec();
        write_handshake_frame(&mut writer, &message).await.unwrap();
        drop(writer);
        let frame = read_frame(&mut reader, true).await.unwrap();
        match frame {
            RawFrame::Handshake(got) => assert_eq!(got, message),
            other => panic!("expected a handshake frame, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn authenticated_frames_round_trip() {
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let header = sample_header();
        let body = vec![0xABu8; header.ciphertext_len as usize];
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
            other => panic!("expected an authenticated frame, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cleartext_frames_are_refused_after_the_handshake() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        write_handshake_frame(&mut writer, b"late").await.unwrap();
        drop(writer);
        let error = read_frame(&mut reader, false).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("cleartext"));
    }

    #[tokio::test]
    async fn oversized_handshake_messages_are_rejected() {
        let (mut writer, mut reader) = tokio::io::duplex(32 * 1024);
        let message = vec![0u8; MAX_HANDSHAKE_MESSAGE + 1];
        let error = write_handshake_frame(&mut writer, &message).await.unwrap_err();
        assert!(error.to_string().contains("exceeds the maximum"));
        // And on the read side: a forged length prefix is refused.
        let mut forged = vec![FRAME_VERSION, FRAME_TYPE_HANDSHAKE];
        forged.extend_from_slice(&u16::MAX.to_be_bytes());
        writer.write_all(&forged).await.unwrap();
        drop(writer);
        assert!(read_frame(&mut reader, true).await.is_err());
    }

    #[tokio::test]
    async fn truncated_frames_surface_as_end_of_stream() {
        let (mut writer, mut reader) = tokio::io::duplex(256);
        writer.write_all(&[FRAME_VERSION, FRAME_TYPE_AUTHENTICATED]).await.unwrap();
        writer.write_all(&[0u8; 10]).await.unwrap();
        drop(writer);
        let error = read_frame(&mut reader, false).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_bad_version_byte_is_refused_immediately() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&[0x00, FRAME_TYPE_AUTHENTICATED]).await.unwrap();
        drop(writer);
        let error = read_frame(&mut reader, false).await.unwrap_err();
        assert!(error.to_string().contains("frame version"));
    }

    #[tokio::test]
    async fn a_body_length_mismatch_is_refused_when_writing() {
        let (mut writer, _reader) = tokio::io::duplex(64);
        let header = sample_header();
        let error = write_authenticated_frame(&mut writer, &header, b"short")
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn wire_lengths_are_reported() {
        assert_eq!(RawFrame::Handshake(vec![0u8; 10]).wire_len(), 14);
        let header = sample_header();
        assert_eq!(
            RawFrame::Authenticated {
                header,
                body: vec![0u8; 32]
            }
            .wire_len(),
            AUTHENTICATED_HEADER_LEN + 32
        );
    }
}

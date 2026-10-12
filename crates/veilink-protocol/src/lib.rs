//! # veilink-protocol
//!
//! `VLP/1`, the Veilink protocol.
//!
//! The protocol has two layers:
//!
//! * [`duplex`] — transport-agnostic stream plumbing shared by both peers: buffered reads,
//!   byte-accounted forwarding and full-duplex splicing with correct half-close behaviour.
//! * the frame and session layer (added with the strict cryptography), which multiplexes many
//!   logical streams over one authenticated outer connection and gives every business frame its own
//!   ephemeral key.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod codec;
pub mod duplex;
pub mod frame;
pub mod message;
pub mod session;

pub use codec::{BucketedPadding, CodecError, PaddingPolicy, SessionCodec, DATA_EPOCH};
pub use duplex::{copy_one_way, splice, BoxStream, BufStream, Duplex, SpliceOutcome};
pub use frame::{
    FrameError, FrameHeader, RawFrame, AUTHENTICATED_HEADER_LEN, FRAME_VERSION, MAX_CIPHERTEXT,
    MAX_HANDSHAKE_MESSAGE, MAX_PADDING, MAX_PAYLOAD,
};
pub use message::{
    Message, MessageError, MessageType, OpenStatus, StreamKind, MAX_HOST_LEN, MAX_TEXT_LEN,
};
pub use session::{
    start_session, IncomingStream, Role, Session, SessionConfig, SessionError, SessionStats,
    SessionStatsSnapshot, VlpStream, DEFAULT_WINDOW, MAX_STREAM_DATA, MIN_WINDOW,
};

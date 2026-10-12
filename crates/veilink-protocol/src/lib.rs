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

pub mod duplex;

pub use duplex::{copy_one_way, splice, BoxStream, BufStream, Duplex, SpliceOutcome};

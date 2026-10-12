//! Directions, frame sequencing and replay rejection.
//!
//! `VLP/1` runs over a reliable, ordered transport (TLS over TCP, or an HTTP/2 stream). Sequence
//! numbers therefore exist to *detect* protocol confusion rather than to reorder anything:
//!
//! * a frame whose sequence number has already been used is a replay;
//! * a frame whose sequence number goes backwards is either a replay or an attempt to reuse a
//!   one-time key;
//! * a gap is a protocol error, because nothing on the path is allowed to drop a frame.
//!
//! Data frames additionally get their own key per frame, so a replay cannot even be decrypted: the
//! recipient's private half was destroyed after the original frame. The sequence check is the
//! second line of defence, and the first one for the control channel.

use crate::CryptoError;

/// Which peer sent a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Direction {
    /// Client to server.
    ClientToServer = 0,
    /// Server to client.
    ServerToClient = 1,
}

impl Direction {
    /// Decodes a direction byte.
    pub fn from_u8(value: u8) -> Result<Self, CryptoError> {
        match value {
            0 => Ok(Direction::ClientToServer),
            1 => Ok(Direction::ServerToClient),
            other => Err(CryptoError::Protocol(format!(
                "unknown frame direction {other}"
            ))),
        }
    }

    /// The wire representation.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// The opposite direction.
    pub fn peer(self) -> Self {
        match self {
            Direction::ClientToServer => Direction::ServerToClient,
            Direction::ServerToClient => Direction::ClientToServer,
        }
    }

    /// A short name for logs.
    pub fn name(self) -> &'static str {
        match self {
            Direction::ClientToServer => "c2s",
            Direction::ServerToClient => "s2c",
        }
    }
}

/// A monotonic sequence number generator for one direction.
#[derive(Debug, Clone, Default)]
pub struct SendSequence {
    next: u64,
}

impl SendSequence {
    /// Starts at zero.
    pub fn new() -> Self {
        SendSequence::default()
    }

    /// Returns the next sequence number and advances.
    ///
    /// Fails at `u64::MAX` rather than wrapping: reusing a sequence number would silently weaken the
    /// replay guarantees.
    pub fn take(&mut self) -> Result<u64, CryptoError> {
        let value = self.next;
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| CryptoError::Protocol("frame sequence number exhausted".to_string()))?;
        Ok(value)
    }

    /// The next value that will be handed out.
    pub fn peek(&self) -> u64 {
        self.next
    }
}

/// How strictly incoming sequence numbers are checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceMode {
    /// Every frame must use exactly the next expected number. Required for the control channel,
    /// whose key chain advances one step per frame.
    Exact,
    /// Every frame must be strictly newer than the last accepted one. Used for data frames, where
    /// a gap can only mean a protocol violation but does not desynchronise a key chain.
    Monotonic,
}

/// Rejects replayed, reordered and skipped frames.
#[derive(Debug, Clone)]
pub struct RecvSequence {
    mode: SequenceMode,
    expected: u64,
    accepted: u64,
}

impl RecvSequence {
    /// Creates a checker starting at zero.
    pub fn new(mode: SequenceMode) -> Self {
        RecvSequence {
            mode,
            expected: 0,
            accepted: 0,
        }
    }

    /// Validates `sequence` without recording it.
    pub fn check(&self, sequence: u64) -> Result<(), CryptoError> {
        let ok = match self.mode {
            SequenceMode::Exact => sequence == self.expected,
            SequenceMode::Monotonic => sequence >= self.expected,
        };
        if ok {
            Ok(())
        } else {
            Err(CryptoError::Replay {
                got: sequence,
                expected: self.expected,
            })
        }
    }

    /// Validates and records `sequence`.
    ///
    /// Call this only after the frame has been authenticated: an unauthenticated frame must not be
    /// able to move the expected value forward.
    pub fn accept(&mut self, sequence: u64) -> Result<(), CryptoError> {
        self.check(sequence)?;
        self.expected = sequence
            .checked_add(1)
            .ok_or_else(|| CryptoError::Protocol("frame sequence number exhausted".to_string()))?;
        self.accepted += 1;
        Ok(())
    }

    /// The next expected sequence number.
    pub fn expected(&self) -> u64 {
        self.expected
    }

    /// How many frames have been accepted.
    pub fn accepted(&self) -> u64 {
        self.accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directions_are_inverses() {
        assert_eq!(Direction::ClientToServer.peer(), Direction::ServerToClient);
        assert_eq!(Direction::ServerToClient.peer(), Direction::ClientToServer);
        for direction in [Direction::ClientToServer, Direction::ServerToClient] {
            assert_eq!(Direction::from_u8(direction.as_u8()).unwrap(), direction);
        }
        assert!(Direction::from_u8(2).is_err());
    }

    #[test]
    fn send_sequence_is_monotonic() {
        let mut sequence = SendSequence::new();
        for expected in 0..8u64 {
            assert_eq!(sequence.take().unwrap(), expected);
        }
        assert_eq!(sequence.peek(), 8);
    }

    #[test]
    fn exact_mode_rejects_replays_and_gaps() {
        let mut checker = RecvSequence::new(SequenceMode::Exact);
        assert!(checker.accept(0).is_ok());
        // A replay of the previous frame.
        assert!(matches!(
            checker.accept(0),
            Err(CryptoError::Replay {
                got: 0,
                expected: 1
            })
        ));
        // A skipped frame would desynchronise the control key chain.
        assert!(checker.accept(2).is_err());
        assert!(checker.accept(1).is_ok());
        assert_eq!(checker.accepted(), 2);
    }

    #[test]
    fn monotonic_mode_accepts_gaps_but_not_regressions() {
        let mut checker = RecvSequence::new(SequenceMode::Monotonic);
        assert!(checker.accept(0).is_ok());
        // A gap is tolerated here: data frames do not drive a key chain.
        assert!(checker.accept(5).is_ok());
        assert!(checker.accept(5).is_err());
        assert!(checker.accept(4).is_err());
        assert!(checker.accept(6).is_ok());
    }

    #[test]
    fn check_does_not_advance_state() {
        let checker = RecvSequence::new(SequenceMode::Exact);
        assert!(checker.check(0).is_ok());
        assert!(checker.check(0).is_ok());
        assert_eq!(checker.expected(), 0);
    }
}

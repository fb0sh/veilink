//! Duplex stream plumbing: buffered reads, byte-accounted forwarding and full-duplex splicing.
//!
//! The proxy must be able to:
//!
//! * read a request or response head of bounded size without consuming a single byte of the body
//!   that follows it (otherwise keep-alive and `CONNECT` tunnelling break);
//! * forward a body with exact byte accounting so that the connection framing stays in sync;
//! * hand the connection over to a raw byte splice after a `101` upgrade.
//!
//! [`BufStream`] keeps an explicit read buffer with a `start`/`end` window rather than wrapping a
//! [`tokio::io::BufReader`], because the buffer has to survive the transition from "parse heads"
//! to "splice bytes".
//!
//! The same buffer is used on both sides of the tunnel, so an upgrade or a `CONNECT` handover
//! behaves identically whether the bytes come from a local socket or from a multiplexed `VLP/1`
//! stream.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Anything that behaves like a TCP connection to the peer.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> Duplex for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// A boxed duplex stream: either a direct `TcpStream` or a multiplexed tunnel stream.
pub type BoxStream = Box<dyn Duplex>;

/// Default read buffer capacity.
pub const DEFAULT_BUFFER_CAPACITY: usize = 16 * 1024;

/// Maximum size of a single header line accepted while scanning a chunked body.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// A buffered duplex stream.
pub struct BufStream<S> {
    inner: S,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    /// Upper bound on how much unread data may be buffered at once.
    limit: usize,
    /// `true` once the peer has closed its write side.
    eof: bool,
}

impl<S: Duplex> BufStream<S> {
    /// Wraps `inner` with the default buffer capacity.
    pub fn new(inner: S) -> Self {
        BufStream::with_limit(inner, DEFAULT_BUFFER_CAPACITY)
    }

    /// Wraps `inner`, buffering at most `limit` unread bytes.
    pub fn with_limit(inner: S, limit: usize) -> Self {
        let limit = limit.max(1024);
        BufStream {
            inner,
            buf: Vec::with_capacity(limit.min(DEFAULT_BUFFER_CAPACITY)),
            start: 0,
            end: 0,
            limit,
            eof: false,
        }
    }

    /// The number of bytes currently buffered but not yet consumed.
    pub fn buffered_len(&self) -> usize {
        self.end - self.start
    }

    /// The buffered bytes.
    pub fn buffered(&self) -> &[u8] {
        &self.buf[self.start..self.end]
    }

    /// True when the peer has closed its write side and the buffer is drained.
    pub fn is_eof(&self) -> bool {
        self.eof && self.buffered_len() == 0
    }

    /// Discards the first `n` buffered bytes.
    pub fn consume(&mut self, n: usize) {
        debug_assert!(n <= self.buffered_len());
        self.start = (self.start + n).min(self.end);
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        }
    }

    /// Access to the underlying stream.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Mutable access to the underlying stream, for writes that bypass the read buffer.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consumes the wrapper, returning the stream and any unread buffered bytes.
    pub fn into_parts(mut self) -> (S, Vec<u8>) {
        let leftover = self.buf[self.start..self.end].to_vec();
        self.start = 0;
        self.end = 0;
        (self.inner, leftover)
    }

    /// Compacts the buffer so that there is room to read more data.
    fn compact(&mut self) {
        if self.start > 0 {
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
    }

    /// Reads more bytes from the peer.
    ///
    /// Returns the number of bytes appended, or `0` at end of stream. Fails with
    /// [`io::ErrorKind::InvalidData`] when the peer sends more than the configured limit without
    /// the caller consuming anything, which bounds proxy memory use.
    pub async fn fill(&mut self) -> io::Result<usize> {
        if self.eof {
            return Ok(0);
        }
        if self.end == self.buf.len() {
            self.compact();
        }
        if self.end == self.buf.len() {
            if self.buf.len() >= self.limit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "peer sent more data than the configured buffer limit allows",
                ));
            }
            let grow = (self.buf.capacity().max(4096) * 2).min(self.limit);
            self.buf.resize(grow, 0);
        }
        let read_from = self.end;
        let n = self.inner.read(&mut self.buf[read_from..]).await?;
        if n == 0 {
            self.eof = true;
            self.buf.truncate(read_from);
            return Ok(0);
        }
        self.end += n;
        Ok(n)
    }

    /// Ensures at least `n` bytes are buffered, returning how many are actually available.
    ///
    /// A return value smaller than `n` means the peer closed the connection.
    pub async fn ensure(&mut self, n: usize) -> io::Result<usize> {
        while self.buffered_len() < n {
            if self.fill().await? == 0 {
                break;
            }
        }
        Ok(self.buffered_len())
    }

    /// Reads a complete header block terminated by `\r\n\r\n`.
    ///
    /// Returns `None` at a clean end of stream before any byte of the new message was read, and
    /// `Some(head)` with the head bytes removed from the buffer otherwise. At most `max` bytes are
    /// accepted; a longer head is rejected with [`io::ErrorKind::InvalidData`].
    pub async fn read_head(&mut self, max: usize) -> io::Result<Option<Vec<u8>>> {
        let mut search_from = 0usize;
        loop {
            let available = self.buffered();
            if available.is_empty() && self.eof {
                return Ok(None);
            }
            let scan_from = search_from.min(available.len());
            if let Some(end) = find_head_end(&available[scan_from..]) {
                let head_len = scan_from + end;
                let head = available[..head_len].to_vec();
                self.consume(head_len);
                return Ok(Some(head));
            }
            search_from = available.len().saturating_sub(3);
            if available.len() > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("header block exceeds the {max} byte limit"),
                ));
            }
            if self.fill().await? == 0 {
                if self.buffered().is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed in the middle of a header block",
                ));
            }
        }
    }

    /// Reads a single `CRLF`- or `LF`-terminated line, including its terminator.
    pub async fn read_line(&mut self, max: usize) -> io::Result<Vec<u8>> {
        loop {
            if let Some(pos) = self.buffered().iter().position(|b| *b == b'\n') {
                let line = self.buffered()[..=pos].to_vec();
                if line.len() > max {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "protocol line exceeds the configured limit",
                    ));
                }
                self.consume(pos + 1);
                return Ok(line);
            }
            if self.buffered_len() > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "protocol line exceeds the configured limit",
                ));
            }
            if self.fill().await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed in the middle of a line",
                ));
            }
        }
    }

    /// Writes everything from the buffer plus `extra` to the peer.
    pub async fn write_all(&mut self, extra: &[u8]) -> io::Result<()> {
        self.inner.write_all(extra).await
    }

    /// Flushes the underlying stream.
    pub async fn flush(&mut self) -> io::Result<()> {
        self.inner.flush().await
    }

    /// Shuts down the write half, leaving the read half open.
    pub async fn shutdown_write(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }

    /// Copies exactly `n` bytes to `dst`.
    pub async fn forward_exact<W>(&mut self, dst: &mut W, n: u64) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut remaining = n;
        while remaining > 0 {
            if self.buffered_len() == 0 && self.fill().await? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("connection closed with {remaining} body bytes outstanding"),
                ));
            }
            let take = self
                .buffered_len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            if take == 0 {
                continue;
            }
            let chunk = &self.buf[self.start..self.start + take];
            dst.write_all(chunk).await?;
            self.consume(take);
            remaining -= take as u64;
        }
        dst.flush().await
    }

    /// Copies every remaining byte to `dst` until the peer closes the connection.
    pub async fn forward_until_eof<W>(&mut self, dst: &mut W) -> io::Result<u64>
    where
        W: AsyncWrite + Unpin,
    {
        let mut total = 0u64;
        loop {
            if self.buffered_len() > 0 {
                let take = self.buffered_len();
                let chunk = self.buf[self.start..self.start + take].to_vec();
                dst.write_all(&chunk).await?;
                self.consume(take);
                total += take as u64;
                continue;
            }
            if self.fill().await? == 0 {
                break;
            }
        }
        dst.flush().await?;
        Ok(total)
    }
}

/// Returns the length of the header block, including its terminator.
///
/// `\r\n\r\n` is the correct terminator, but a bare `\n\n` and a mixed `\n\r\n` are accepted
/// too: being strict here would only produce confusing 400 responses for clients that are otherwise
/// fine. The returned value is the number of bytes to consume, i.e. the index just past the
/// terminating blank line.
fn find_head_end(haystack: &[u8]) -> Option<usize> {
    let mut idx = 0usize;
    while idx < haystack.len() {
        if haystack[idx] == b'\n' {
            if idx + 1 < haystack.len() && haystack[idx + 1] == b'\n' {
                return Some(idx + 2);
            }
            if idx + 2 < haystack.len() && haystack[idx + 1] == b'\r' && haystack[idx + 2] == b'\n'
            {
                return Some(idx + 3);
            }
        }
        idx += 1;
    }
    None
}

/// Reads from `a` and writes to `b` until either side closes, then half-closes `b`.
///
/// This is the correct full-duplex pump for tunnelled traffic: no data is lost when one direction
/// finishes first, and the peer still sees a clean FIN. The destination is half-closed even when
/// the copy failed, so that the opposite direction of a splice always unblocks instead of
/// deadlocking on a peer that is waiting for our FIN.
pub async fn copy_one_way<A, B>(a: &mut A, b: &mut B) -> io::Result<u64>
where
    A: AsyncRead + Unpin,
    B: AsyncWrite + Unpin,
{
    let copied = tokio::io::copy(a, b).await;
    let _ = b.shutdown().await;
    copied
}

/// The outcome of a full-duplex splice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceOutcome {
    /// Bytes copied from `a` to `b`.
    pub a_to_b: u64,
    /// Bytes copied from `b` to `a`.
    pub b_to_a: u64,
}

/// Runs a full-duplex byte splice between two duplex streams until both directions finish.
///
/// Each direction half-closes its destination when it stops, which is what makes TCP half-close
/// semantics work through a tunnel: a peer that has finished sending still receives everything the
/// other side sends afterwards.
pub async fn splice<A, B>(a: &mut BufStream<A>, b: &mut BufStream<B>) -> io::Result<SpliceOutcome>
where
    A: Duplex,
    B: Duplex,
{
    // Flush anything already buffered in either direction before switching to raw copying. The
    // flushed bytes count towards the reported totals.
    let a_buffered = a.buffered().to_vec();
    let mut a_to_b = a_buffered.len() as u64;
    if !a_buffered.is_empty() {
        a.consume(a_buffered.len());
        b.inner_mut().write_all(&a_buffered).await?;
        b.inner_mut().flush().await?;
    }
    let b_buffered = b.buffered().to_vec();
    let mut b_to_a = b_buffered.len() as u64;
    if !b_buffered.is_empty() {
        b.consume(b_buffered.len());
        a.inner_mut().write_all(&b_buffered).await?;
        a.inner_mut().flush().await?;
    }

    // `tokio::io::split` on a `&mut` reference gives both halves without taking ownership, which
    // keeps connection teardown under the caller's control.
    let (mut a_read, mut a_write) = tokio::io::split(a.inner_mut());
    let (mut b_read, mut b_write) = tokio::io::split(b.inner_mut());
    let up = copy_one_way(&mut a_read, &mut b_write);
    let down = copy_one_way(&mut b_read, &mut a_write);
    let (up, down) = tokio::join!(up, down);
    a_to_b += up?;
    b_to_a += down?;
    Ok(SpliceOutcome { a_to_b, b_to_a })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn buffered_read_head_preserves_body() {
        let (mut a, b) = duplex(4096);
        let mut stream = BufStream::new(b);
        a.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nBODYBYTES")
            .await
            .unwrap();
        let head = stream.read_head(8192).await.unwrap().unwrap();
        assert_eq!(head, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(stream.buffered(), b"BODYBYTES");
    }

    #[tokio::test]
    async fn read_head_handles_split_writes() {
        let (mut a, b) = duplex(4096);
        let mut stream = BufStream::new(b);
        let writer = tokio::spawn(async move {
            a.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
            tokio::task::yield_now().await;
            a.write_all(b"Host: x\r\n\r\nrest").await.unwrap();
            a
        });
        let head = stream.read_head(8192).await.unwrap().unwrap();
        assert_eq!(head, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(stream.buffered(), b"rest");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn read_head_rejects_oversized_headers() {
        let (mut a, b) = duplex(65536);
        let mut stream = BufStream::new(b);
        tokio::spawn(async move {
            let filler = vec![b'x'; 4096];
            for _ in 0..8 {
                if a.write_all(&filler).await.is_err() {
                    return;
                }
            }
        });
        let err = stream.read_head(1024).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_head_returns_none_at_clean_eof() {
        let (a, b) = duplex(64);
        drop(a);
        let mut stream = BufStream::new(b);
        assert!(stream.read_head(1024).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn read_head_reports_truncated_head() {
        let (mut a, b) = duplex(64);
        let mut stream = BufStream::new(b);
        a.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
        drop(a);
        let err = stream.read_head(1024).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn forward_exact_moves_exactly_n_bytes() {
        let (mut a, b) = duplex(4096);
        let mut src = BufStream::new(b);
        a.write_all(b"0123456789tail").await.unwrap();
        let (mut sink_read, mut sink_write) = duplex(4096);
        src.forward_exact(&mut sink_write, 10).await.unwrap();
        drop(sink_write);

        let mut got = Vec::new();
        sink_read.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"0123456789");
        // `tail` is still pending for the next message on the same connection.
        assert_eq!(src.buffered(), b"tail");
    }

    #[tokio::test]
    async fn forward_exact_detects_truncation() {
        let (mut a, b) = duplex(4096);
        let mut src = BufStream::new(b);
        a.write_all(b"short").await.unwrap();
        drop(a);
        let (mut _r, mut w) = duplex(4096);
        let err = src.forward_exact(&mut w, 100).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn forward_until_eof_copies_everything() {
        let (mut a, b) = duplex(4096);
        let mut src = BufStream::new(b);
        tokio::spawn(async move {
            a.write_all(&vec![b'z'; 100_000]).await.unwrap();
        });
        let (mut r, mut w) = duplex(65_536);
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            r.read_to_end(&mut got).await.unwrap();
            got
        });
        let total = src.forward_until_eof(&mut w).await.unwrap();
        drop(w);
        assert_eq!(total, 100_000);
        assert_eq!(reader.await.unwrap().len(), 100_000);
    }

    #[tokio::test]
    async fn read_line_handles_lf_terminators() {
        let (mut a, b) = duplex(1024);
        let mut src = BufStream::new(b);
        a.write_all(b"5\r\nhello\n0\r\n\r\n").await.unwrap();
        assert_eq!(src.read_line(64).await.unwrap(), b"5\r\n");
        assert_eq!(src.read_line(64).await.unwrap(), b"hello\n");
    }

    #[tokio::test]
    async fn into_parts_returns_leftovers() {
        let (mut a, b) = duplex(1024);
        let mut src = BufStream::new(b);
        a.write_all(b"abc").await.unwrap();
        src.ensure(3).await.unwrap();
        let (_inner, leftover) = src.into_parts();
        assert_eq!(leftover, b"abc");
    }

    #[tokio::test]
    async fn splice_moves_buffered_and_live_bytes_both_ways() {
        let (mut a_peer, a) = duplex(4096);
        let (mut b_peer, b) = duplex(4096);
        let mut a = BufStream::new(a);
        let mut b = BufStream::new(b);

        // Pre-buffer bytes on both sides, as an upgraded connection would.
        a_peer.write_all(b"from-a").await.unwrap();
        b_peer.write_all(b"from-b").await.unwrap();
        a.ensure(6).await.unwrap();
        b.ensure(6).await.unwrap();

        let splicer = tokio::spawn(async move {
            let outcome = splice(&mut a, &mut b).await.unwrap();
            outcome
        });

        // Each peer should now see the other side's buffered bytes.
        let mut got_a = [0u8; 6];
        a_peer.read_exact(&mut got_a).await.unwrap();
        assert_eq!(&got_a, b"from-b");
        let mut got_b = [0u8; 6];
        b_peer.read_exact(&mut got_b).await.unwrap();
        assert_eq!(&got_b, b"from-a");

        // Live bytes keep flowing in both directions.
        a_peer.write_all(b"ping").await.unwrap();
        let mut got_b2 = [0u8; 4];
        b_peer.read_exact(&mut got_b2).await.unwrap();
        assert_eq!(&got_b2, b"ping");

        // Half-close from a propagates as a FIN to b's peer.
        a_peer.shutdown().await.unwrap();
        let mut rest = Vec::new();
        b_peer.read_to_end(&mut rest).await.unwrap();

        // The other direction still carries data, and half-closing b ends it cleanly.
        b_peer.write_all(b"bye").await.unwrap();
        b_peer.shutdown().await.unwrap();
        let mut got_a2 = Vec::new();
        a_peer.read_to_end(&mut got_a2).await.unwrap();
        assert_eq!(got_a2, b"bye");

        // `from-a` (6) + `ping` (4) went a -> b; `from-b` (6) + `bye` (3) went b -> a.
        let outcome = splicer.await.unwrap();
        assert_eq!(outcome.a_to_b, 10);
        assert_eq!(outcome.b_to_a, 9);
    }

    #[test]
    fn detects_head_terminators() {
        // The returned value is the head length, terminator included.
        assert_eq!(find_head_end(b"a\r\n\r\n"), Some(5));
        assert_eq!(find_head_end(b"a\n\n"), Some(3));
        assert_eq!(find_head_end(b"a\r\n\nb"), Some(4));
        assert_eq!(find_head_end(b"a\n\r\nb"), Some(4));
        assert_eq!(find_head_end(b"a\r\nb"), None);
        assert_eq!(find_head_end(b""), None);
        assert_eq!(
            find_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nBODY"),
            Some(27)
        );
    }
}

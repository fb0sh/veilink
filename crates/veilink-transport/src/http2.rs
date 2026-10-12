//! Carrying the `VLP/1` byte stream inside one HTTP/2 request/response body pair.
//!
//! HTTP/2 is used as a *carrier*, not as a protocol: the client opens a single long-lived `POST`
//! request with a streaming body, the server answers `200` with a streaming body, and from then on
//! each direction is a byte pipe. `VLP/1` runs inside it and provides the real multiplexing,
//! encryption and framing.
//!
//! The reason to do this at all is that the outer traffic then looks like an ordinary HTTP/2
//! session to a middlebox: a TLS connection with an `h2` ALPN, one stream, and a stream of DATA
//! frames. It is a plausible-deniability measure, not a security control — the security comes from
//! `VLP/1` either way, and the same session runs identically over the plain
//! [`tls`](crate::tls) framing.
//!
//! HTTP/2 permits a server to send response data before the request body is complete, which is
//! exactly what a full-duplex tunnel needs. Both peers therefore start writing as soon as the
//! stream is established; neither waits for the other's body to finish.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::Request;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

use crate::connector::{accept_expecting, connect_expecting};
use crate::tls::{TlsError, ALPN_H2};

/// Size of each HTTP/2 DATA frame written by the tunnel.
const H2_WRITE_CHUNK: usize = 16 * 1024;

/// A duplex byte stream carried by one HTTP/2 stream.
pub struct H2Duplex {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    pending: BytesMut,
    /// Capacity already requested from the HTTP/2 flow controller.
    reserved: usize,
    eof: bool,
    finished: bool,
}

impl std::fmt::Debug for H2Duplex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Duplex")
            .field("buffered", &self.pending.len())
            .field("eof", &self.eof)
            .finish()
    }
}

impl H2Duplex {
    /// Wraps an established HTTP/2 stream pair.
    pub fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        H2Duplex {
            send,
            recv,
            pending: BytesMut::new(),
            reserved: 0,
            eof: false,
            finished: false,
        }
    }
}

impl AsyncRead for H2Duplex {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let this = self.get_mut();

        if !this.pending.is_empty() {
            let take = buf.remaining().min(this.pending.len());
            let chunk = this.pending.split_to(take);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        if this.eof {
            return Poll::Ready(Ok(()));
        }

        match this.recv.poll_data(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(std::io::Error::other(format!(
                "HTTP/2 stream error: {error}"
            )))),
            Poll::Ready(Some(Ok(data))) => {
                // The bytes are moved into our own buffer, so the HTTP/2 flow-control window may
                // be released immediately. End-to-end backpressure is provided by the `VLP/1`
                // stream windows, which are the ones that actually carry application semantics.
                let len = data.len();
                if let Err(error) = this.recv.flow_control().release_capacity(len) {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "cannot release HTTP/2 flow-control capacity: {error}"
                    ))));
                }
                this.pending.extend_from_slice(&data);
                let take = buf.remaining().min(this.pending.len());
                let chunk = this.pending.split_to(take);
                buf.put_slice(&chunk);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for H2Duplex {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.finished {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the HTTP/2 stream was closed",
            )));
        }

        let want = buf.len().min(H2_WRITE_CHUNK);
        // Ask for capacity at most once per change of intent; re-requesting every poll is
        // harmless but noisy.
        if this.reserved < want {
            this.send.reserve_capacity(want);
            this.reserved = want;
        }

        match this.send.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the peer stopped reading the HTTP/2 stream",
            ))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(std::io::Error::other(format!(
                "HTTP/2 send error: {error}"
            )))),
            Poll::Ready(Some(Ok(capacity))) => {
                let take = capacity.min(want).min(buf.len());
                this.reserved = this.reserved.saturating_sub(take);
                let data = Bytes::copy_from_slice(&buf[..take]);
                match this.send.send_data(data, false) {
                    Ok(()) => Poll::Ready(Ok(take)),
                    Err(error) => Poll::Ready(Err(std::io::Error::other(format!(
                        "HTTP/2 send error: {error}"
                    )))),
                }
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // `send_data` hands the bytes to the connection driver immediately.
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let this = self.get_mut();
        if !this.finished {
            this.finished = true;
            this.send
                .send_data(Bytes::new(), true)
                .map_err(|e| std::io::Error::other(format!("HTTP/2 close error: {e}")))?;
        }
        Poll::Ready(Ok(()))
    }
}

/// An established HTTP/2 tunnel plus its connection driver.
pub struct H2Tunnel<D> {
    /// The byte pipe carrying `VLP/1`.
    pub duplex: H2Duplex,
    /// The TLS exporter of the underlying session.
    pub exporter: [u8; 32],
    /// The connection driver. Dropping it tears the HTTP/2 connection down.
    pub driver: D,
}

impl<D> std::fmt::Debug for H2Tunnel<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Tunnel")
            .field("exporter", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Opens an HTTP/2 tunnel to `addr`.
pub async fn connect(
    addr: SocketAddr,
    server_name: &str,
    timeout: Duration,
) -> Result<H2Tunnel<tokio::task::JoinHandle<()>>, TlsError> {
    let config = crate::tls::client_config_for(Some(ALPN_H2))?;
    let secure = connect_expecting(addr, server_name, config, timeout, Some(ALPN_H2)).await?;
    if secure.alpn.as_deref() != Some(ALPN_H2) {
        return Err(TlsError::UnexpectedAlpn(
            secure
                .alpn
                .as_deref()
                .map(|a| String::from_utf8_lossy(a).to_string())
                .unwrap_or_else(|| "none".to_string()),
        ));
    }
    let exporter = secure.exporter;

    let (mut send_request, connection) =
        tokio::time::timeout(timeout, h2::client::handshake(secure.stream))
            .await
            .map_err(|_| TlsError::Handshake("the HTTP/2 handshake timed out".to_string()))?
            .map_err(|e| TlsError::Handshake(format!("HTTP/2 handshake failed: {e}")))?;

    let driver = tokio::spawn(async move {
        if let Err(error) = connection.await {
            debug!(error = %error, "HTTP/2 connection driver stopped");
        }
    });

    let request = Request::builder()
        .method("POST")
        .uri("https://veilink.invalid/v1")
        .header("content-type", "application/octet-stream")
        .body(())
        .map_err(|e| TlsError::Handshake(format!("cannot build the HTTP/2 request: {e}")))?;

    let (response, send) = send_request
        .send_request(request, false)
        .map_err(|e| TlsError::Handshake(format!("cannot open an HTTP/2 stream: {e}")))?;

    let response = tokio::time::timeout(timeout, response)
        .await
        .map_err(|_| {
            TlsError::Handshake("the server did not answer the tunnel request".to_string())
        })?
        .map_err(|e| TlsError::Handshake(format!("HTTP/2 response failed: {e}")))?;
    if response.status() != http::StatusCode::OK {
        return Err(TlsError::Handshake(format!(
            "the server refused the tunnel with status {}",
            response.status()
        )));
    }
    let recv = response.into_body();

    Ok(H2Tunnel {
        duplex: H2Duplex::new(send, recv),
        exporter,
        driver,
    })
}

/// Accepts an HTTP/2 tunnel on an accepted TCP socket.
pub async fn accept(
    socket: TcpStream,
    acceptor: &tokio_rustls::TlsAcceptor,
    timeout: Duration,
) -> Result<H2Tunnel<tokio::task::JoinHandle<()>>, TlsError> {
    let secure = accept_expecting(socket, acceptor, timeout, ALPN_H2).await?;
    if secure.alpn.as_deref() != Some(ALPN_H2) {
        return Err(TlsError::UnexpectedAlpn(
            secure
                .alpn
                .as_deref()
                .map(|a| String::from_utf8_lossy(a).to_string())
                .unwrap_or_else(|| "none".to_string()),
        ));
    }
    let exporter = secure.exporter;

    let mut connection = tokio::time::timeout(timeout, h2::server::handshake(secure.stream))
        .await
        .map_err(|_| TlsError::Handshake("the HTTP/2 handshake timed out".to_string()))?
        .map_err(|e| TlsError::Handshake(format!("HTTP/2 handshake failed: {e}")))?;

    let accepted = tokio::time::timeout(timeout, connection.accept())
        .await
        .map_err(|_| TlsError::Handshake("the peer never opened a tunnel stream".to_string()))?;
    let (request, mut respond) = match accepted {
        Some(Ok(pair)) => pair,
        Some(Err(error)) => {
            return Err(TlsError::Handshake(format!(
                "HTTP/2 stream failed: {error}"
            )))
        }
        None => {
            return Err(TlsError::Handshake(
                "the peer closed the HTTP/2 connection without opening a stream".to_string(),
            ))
        }
    };

    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(())
        .map_err(|e| TlsError::Handshake(format!("cannot build the HTTP/2 response: {e}")))?;
    let send = respond
        .send_response(response, false)
        .map_err(|e| TlsError::Handshake(format!("cannot answer the tunnel request: {e}")))?;
    let recv = request.into_body();

    // Keep the connection alive and refuse any further stream: one session per connection.
    let driver = tokio::spawn(async move {
        while let Some(accepted) = connection.accept().await {
            match accepted {
                Ok((_request, mut respond)) => {
                    let refusal = http::Response::builder()
                        .status(http::StatusCode::CONFLICT)
                        .body(())
                        .expect("a constant response is valid");
                    let _ = respond.send_response(refusal, true);
                }
                Err(error) => {
                    debug!(error = %error, "HTTP/2 connection ended");
                    break;
                }
            }
        }
    });

    Ok(H2Tunnel {
        duplex: H2Duplex::new(send, recv),
        exporter,
        driver,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ServerTlsIdentity;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn tunnel_pair() -> (
        H2Duplex,
        H2Duplex,
        [u8; 32],
        [u8; 32],
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let identity = ServerTlsIdentity::generate(&["localhost".to_string()]).unwrap();
        let acceptor = crate::connector::acceptor(&identity).unwrap();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let tunnel = accept(socket, &acceptor, Duration::from_secs(5))
                .await
                .unwrap();
            (tunnel.duplex, tunnel.exporter, tunnel.driver)
        });

        let client = connect(addr, "localhost", Duration::from_secs(5))
            .await
            .unwrap();
        let (server_duplex, server_exporter, server_driver) = server.await.unwrap();
        (
            client.duplex,
            server_duplex,
            client.exporter,
            server_exporter,
            client.driver,
            server_driver,
        )
    }

    #[tokio::test]
    async fn carries_bytes_in_both_directions() {
        let (mut client, mut server, client_exporter, server_exporter, _cd, _sd) =
            tunnel_pair().await;
        assert_eq!(client_exporter, server_exporter);

        client.write_all(b"hello over h2").await.unwrap();
        client.flush().await.unwrap();
        let mut got = vec![0u8; 13];
        tokio::time::timeout(Duration::from_secs(5), server.read_exact(&mut got))
            .await
            .expect("server read timed out")
            .unwrap();
        assert_eq!(got, b"hello over h2");

        server.write_all(b"and back").await.unwrap();
        server.flush().await.unwrap();
        let mut back = vec![0u8; 8];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut back))
            .await
            .expect("client read timed out")
            .unwrap();
        assert_eq!(back, b"and back");
    }

    #[tokio::test]
    async fn carries_a_large_transfer() {
        let (mut client, mut server, _ce, _se, _cd, _sd) = tunnel_pair().await;
        const SIZE: usize = 1024 * 1024;
        let payload: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();

        // The client's receive half must stay alive until the server has read everything: dropping
        // it would make HTTP/2 reset the stream, which is correct behaviour but not what this test
        // is measuring.
        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client.shutdown().await.unwrap();
            client
        });
        let mut received = Vec::with_capacity(SIZE);
        tokio::time::timeout(Duration::from_secs(20), server.read_to_end(&mut received))
            .await
            .expect("large HTTP/2 transfer timed out")
            .unwrap();
        let client = writer.await.unwrap();
        assert_eq!(received.len(), SIZE);
        assert_eq!(received, expected);
        drop(client);
    }

    #[tokio::test]
    async fn a_half_close_is_visible_to_the_peer() {
        let (mut client, mut server, _ce, _se, _cd, _sd) = tunnel_pair().await;
        client.write_all(b"last").await.unwrap();
        client.shutdown().await.unwrap();
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), server.read_to_end(&mut got))
            .await
            .expect("the server never saw the end of stream")
            .unwrap();
        assert_eq!(got, b"last");
    }

    #[tokio::test]
    async fn a_second_stream_on_the_same_connection_is_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let identity = ServerTlsIdentity::generate(&["localhost".to_string()]).unwrap();
        let acceptor = crate::connector::acceptor(&identity).unwrap();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            accept(socket, &acceptor, Duration::from_secs(5)).await
        });

        let config = crate::tls::client_config().unwrap();
        let secure = crate::connect_with(addr, "localhost", config, Duration::from_secs(5))
            .await
            .unwrap();
        let (mut send_request, connection) = h2::client::handshake(secure.stream).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });

        let request = || {
            Request::builder()
                .method("POST")
                .uri("https://veilink.invalid/v1")
                .body(())
                .unwrap()
        };
        let (first, _send) = send_request.send_request(request(), false).unwrap();
        let response = first.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);

        let (second, _send2) = send_request.send_request(request(), false).unwrap();
        let response = second.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::CONFLICT);

        let tunnel = server.await.unwrap().unwrap();
        drop(tunnel);
        drop(driver);
    }
}

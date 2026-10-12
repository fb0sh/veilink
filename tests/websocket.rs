//! WebSocket / HTTP `Upgrade` forwarding.
//!
//! After a `101 Switching Protocols` response the proxy stops interpreting HTTP and becomes a raw
//! byte splice. These tests check the handshake, the byte exchange in both directions, and that
//! bytes pipelined by the client immediately after its request are not lost.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use veilink_testkit::settings::{client_settings_fast, RunningClient};
use veilink_testkit::TestServer;

/// Reads a response head from `socket`, returning it along with any bytes read past it.
async fn read_head(socket: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        let n = socket.read(&mut chunk).await.expect("read");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos + 4]).to_string();
            let rest = buf[pos + 4..].to_vec();
            return (head, rest);
        }
    }
    (String::from_utf8_lossy(&buf).to_string(), Vec::new())
}

async fn upgraded_pair(
    proxy: std::net::SocketAddr,
    origin: std::net::SocketAddr,
) -> tokio::net::TcpStream {
    let mut socket = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let request = format!(
        "GET http://{origin}/upgrade HTTP/1.1\r\n\
         Host: {origin}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let (head, _rest) = read_head(&mut socket).await;
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected 101 Switching Protocols, got: {head}"
    );
    assert!(head.contains("Upgrade: websocket"), "{head}");
    socket
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upgrades_and_echoes_bytes_in_both_directions() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    let mut socket = upgraded_pair(client.addr, origin.addr()).await;

    for payload in [
        &b"first-frame"[..],
        b"second-frame",
        b"\x00\x01\x02\xff\xfe",
    ] {
        socket.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut got))
            .await
            .expect("timed out waiting for the echo")
            .expect("echo read");
        assert_eq!(got, payload, "payload was altered by the tunnel");
    }

    // The proxy must propagate a clean close in both directions.
    socket.shutdown().await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut rest))
        .await
        .expect("timed out waiting for the tunnel to close")
        .expect("close read");

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bytes_pipelined_with_the_upgrade_request_are_not_lost() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    // Send the upgrade request and the first data frame in a single write, before the 101 arrives.
    let mut socket = tokio::net::TcpStream::connect(client.addr).await.unwrap();
    let origin_addr = origin.addr();
    let mut request = format!(
        "GET http://{origin_addr}/upgrade HTTP/1.1\r\n\
         Host: {origin_addr}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\r\n"
    )
    .into_bytes();
    request.extend_from_slice(b"early-bytes");
    socket.write_all(&request).await.unwrap();

    let (head, rest) = read_head(&mut socket).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");

    // The early bytes were buffered while the head was parsed; they must arrive as an echo.
    let mut got = rest;
    while got.len() < b"early-bytes".len() {
        let mut chunk = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut chunk))
            .await
            .expect("timed out waiting for the buffered frame")
            .expect("read");
        if n == 0 {
            break;
        }
        got.extend_from_slice(&chunk[..n]);
    }
    assert!(
        got.starts_with(b"early-bytes"),
        "buffered upgrade bytes were lost: {got:?}"
    );

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_upgrade_request_to_an_upgrade_route_is_rejected_by_the_origin() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    let result = veilink_testkit::curl::get_via_proxy_with_status(
        client.addr,
        &format!("{}/upgrade", origin.origin()),
    );
    result.expect_ok("plain request to the upgrade route");
    assert_eq!(result.status(), 400);

    client.stop().await;
    origin.stop().await;
}

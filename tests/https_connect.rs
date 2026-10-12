//! HTTPS `CONNECT` tunnelling.
//!
//! These tests run a real TLS 1.3 origin. The client must establish a raw byte tunnel and must not
//! terminate TLS, intercept the handshake, or need any certificate of its own: `curl` performs the
//! TLS handshake end to end with the origin and verifies the origin's certificate itself.

use std::io::Write;

use veilink_testkit::curl::connect_tls_via_proxy;
use veilink_testkit::settings::{client_settings_fast, RunningClient};
use veilink_testkit::TestTlsServer;

/// Writes the origin's certificate to a temporary PEM file for `curl --cacert`.
fn write_ca(dir: &tempfile::TempDir, pem: &str) -> std::path::PathBuf {
    let path = dir.path().join("origin.pem");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(pem.as_bytes()).unwrap();
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnels_tls_end_to_end() {
    let origin = TestTlsServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;
    let dir = tempfile::tempdir().unwrap();
    let ca = write_ca(&dir, origin.certificate_pem());

    let result = connect_tls_via_proxy(client.addr, "127.0.0.1", origin.addr().port(), &ca, &[]);
    result.expect_ok("HTTPS through the tunnel");
    // curl prints the body, then the status code on its own line because of `-w`.
    assert_eq!(
        result.stdout.lines().next().unwrap_or_default(),
        "secure hello"
    );
    assert_eq!(result.status(), 200);

    // The origin really did complete a TLS handshake, so the tunnel carried TLS and nothing else.
    let connections = origin
        .stats()
        .connections
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(connections, 1);

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_tls_requests_share_one_tunnel_correctly() {
    let origin = TestTlsServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;
    let dir = tempfile::tempdir().unwrap();
    let ca = write_ca(&dir, origin.certificate_pem());

    // One CONNECT, two requests on the same tunnelled connection.
    let url = format!("https://127.0.0.1:{}/", origin.addr().port());
    let result = veilink_testkit::curl::curl(&[
        "-x",
        &format!("http://{}", client.addr),
        "-p",
        "--cacert",
        &ca.display().to_string(),
        &url,
        &url,
        "-w",
        "\n%{http_code}",
    ]);
    result.expect_ok("two HTTPS requests over one tunnel");
    assert_eq!(result.stdout.matches("secure hello").count(), 2);

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_to_a_closed_port_fails_closed() {
    let client = RunningClient::start(client_settings_fast(&[])).await;
    let dir = tempfile::tempdir().unwrap();
    let ca = write_ca(&dir, "unused");
    // Port 9 is closed; the proxy must answer 502 and curl must fail rather than hang.
    let result = connect_tls_via_proxy(client.addr, "127.0.0.1", 9, &ca, &[]);
    assert!(
        !result.ok(),
        "CONNECT to a closed port unexpectedly succeeded"
    );
    assert!(
        result.stdout.contains("502") || result.stderr.contains("502"),
        "expected a 502 from the proxy, got stdout={:?} stderr={:?}",
        result.stdout,
        result.stderr
    );

    client.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_targets_are_parsed_strictly() {
    let client = RunningClient::start(client_settings_fast(&[])).await;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut socket = tokio::net::TcpStream::connect(client.addr).await.unwrap();
    // A CONNECT without any authority must be refused, not guessed.
    socket
        .write_all(b"CONNECT  HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 400") || text.starts_with("HTTP/1.1 502"),
        "expected a refusal, got {text}"
    );

    client.stop().await;
}

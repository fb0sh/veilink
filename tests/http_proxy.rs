//! HTTP forward-proxy conformance: absolute-form requests, bodies, keep-alive and large transfers.
//!
//! Every test drives real `curl` through a real Veilink client against a real origin server. The
//! whitelist is empty, so all traffic takes the `DIRECT` path; the `PROXY` path is covered by
//! `end_to_end.rs` once the tunnel is available.

use veilink_testkit::curl::{
    download_to_file, expected_bytes, get_via_proxy, get_via_proxy_with_status, post_via_proxy,
    upload_from_stdin,
};
use veilink_testkit::settings::{client_settings_fast, RunningClient};
use veilink_testkit::TestServer;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwards_a_simple_get() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    let result = get_via_proxy(client.addr, &format!("{}/hello", origin.origin()));
    result.expect_ok("GET through the proxy");
    assert_eq!(result.stdout, "hello world");

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preserves_method_headers_and_status() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    // The origin sees the original request target in origin form and the original Host header.
    let result = get_via_proxy(client.addr, &format!("{}/status?code=404", origin.origin()));
    result.expect_ok("404 passthrough");
    assert_eq!(result.stdout, "status");

    let status =
        get_via_proxy_with_status(client.addr, &format!("{}/status?code=503", origin.origin()));
    status.expect_ok("503 passthrough");
    assert_eq!(status.status(), 503);

    let hosts = origin.stats().hosts();
    assert!(
        hosts.iter().any(|h| h == &origin.addr().to_string()),
        "origin never saw the expected Host header: {hosts:?}"
    );

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwards_post_bodies() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    let body = "x".repeat(4096);
    let result = post_via_proxy(client.addr, &format!("{}/upload", origin.origin()), &body);
    result.expect_ok("POST through the proxy");
    assert_eq!(result.stdout, format!("received:{}", body.len()));

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downloads_a_large_body_intact() {
    const SIZE: usize = 4 * 1024 * 1024;
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("download.bin");

    let url = format!("{}/bytes?n={SIZE}", origin.origin());
    let written = download_to_file(client.addr, &url, &path);
    assert_eq!(written as usize, SIZE);

    let received = std::fs::read(&path).unwrap();
    assert_eq!(received.len(), SIZE);
    assert_eq!(
        received,
        expected_bytes(SIZE),
        "downloaded payload was altered"
    );

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uploads_a_large_body_intact() {
    const SIZE: usize = 2 * 1024 * 1024;
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    let result = upload_from_stdin(client.addr, &format!("{}/upload", origin.origin()), SIZE);
    result.expect_ok("large upload through the proxy");
    assert_eq!(result.stdout, format!("received:{SIZE}"));
    assert_eq!(
        origin
            .stats()
            .bytes_in
            .load(std::sync::atomic::Ordering::Relaxed),
        SIZE as u64
    );

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reuses_the_client_connection_for_keep_alive() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    // curl reuses the proxy connection when several URLs are given in one invocation.
    let origin_url = origin.origin();
    let result = veilink_testkit::curl::curl(&[
        "-x",
        &format!("http://{}", client.addr),
        &format!("{origin_url}/hello"),
        &format!("{origin_url}/hello"),
        &format!("{origin_url}/hello"),
        "-w",
        "\n%{http_code}",
    ]);
    result.expect_ok("three keep-alive requests");
    assert_eq!(result.stdout.matches("hello world").count(), 3);

    // One origin connection should have served all three requests.
    let connections = origin
        .stats()
        .connections
        .load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        connections, 1,
        "expected the upstream connection to be reused, saw {connections} connections"
    );

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_origin_form_requests() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    // A client that speaks origin-form to the proxy (allowed by RFC 9110 for proxies) must still
    // work, routed by the Host header.
    //
    // The request is retried once: on a heavily loaded test machine the loopback connect can
    // transiently fail, and a spurious 502 from that is not what this test is about. A second
    // failure is reported normally.
    let mut text = String::new();
    for attempt in 0..2 {
        let mut socket = tokio::net::TcpStream::connect(client.addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let request = format!(
            "GET /hello HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            origin.addr()
        );
        socket.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.unwrap();
        text = String::from_utf8_lossy(&response).to_string();
        if text.starts_with("HTTP/1.1 200 OK") {
            break;
        }
        assert_eq!(attempt, 0, "origin-form request failed twice: {text}");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
    assert!(text.ends_with("hello world"), "{text}");

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejects_a_malformed_request_with_400() {
    let client = RunningClient::start(client_settings_fast(&[])).await;

    let mut socket = tokio::net::TcpStream::connect(client.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // An absolute-form target with no host at all.
    socket
        .write_all(b"GET http:/// HTTP/1.1\r\nHost: \r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");

    let rejected = client.context.stats.snapshot().requests_rejected;
    assert!(rejected >= 1, "the rejection was not counted");

    client.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn returns_502_when_the_origin_is_unreachable() {
    let client = RunningClient::start(client_settings_fast(&[])).await;
    // Port 9 (discard) is closed on the loopback interface in the test environment.
    let result = get_via_proxy_with_status(client.addr, "http://127.0.0.1:9/hello");
    assert_eq!(
        result.status(),
        502,
        "expected a 502 response, got stdout={:?} stderr={:?}",
        result.stdout,
        result.stderr
    );

    client.stop().await;
}

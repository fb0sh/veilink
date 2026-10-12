//! End-to-end tests: a real client, a real server, a real origin, and real `curl` in front.
//!
//! These are the tests that answer the question "does Veilink actually work". Everything else
//! checks a component; this checks the whole path.

use std::time::Duration;

use veilink_config::Transport;
use veilink_crypto::Psk;
use veilink_testkit::curl::{get_via_proxy_with_host, get_via_proxy_with_status};
use veilink_testkit::settings::TEST_KEY;
use veilink_testkit::{RunningServer, RunningTunnelClient, TestServer, TestTlsServer};

fn test_psk() -> Psk {
    Psk::parse(TEST_KEY).unwrap()
}

async fn proxied_setup(transport: Transport) -> (TestServer, RunningServer, RunningTunnelClient) {
    let origin = TestServer::start().await.unwrap();
    let key = test_psk();
    let server = RunningServer::start(&key, transport).await;
    let client = RunningTunnelClient::start(
        &key,
        server.addr,
        &["CIDR,127.0.0.0/8"],
        transport,
        "veilink.local",
    )
    .await;
    client.wait_ready(Duration::from_secs(15)).await;
    (origin, server, client)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxies_http_through_the_encrypted_tunnel() {
    let (origin, server, client) = proxied_setup(Transport::Tls).await;

    let result = get_via_proxy_with_status(client.addr, &format!("{}/hello", origin.origin()));
    assert_eq!(result.status(), 200, "stdout={:?}", result.stdout);
    assert_eq!(result.stdout.lines().next(), Some("hello world"));

    // The traffic really went through the server: it counted a stream, and the client counted a
    // proxied request.
    let client_stats = client.context.stats.snapshot();
    assert_eq!(client_stats.requests_proxied, 1);
    assert_eq!(client_stats.requests_direct, 0);
    assert!(
        server.context.stats.snapshot().streams_total >= 1,
        "the server never saw a stream"
    );

    client.stop().await;
    server.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxies_http_over_an_http2_tunnel() {
    let (origin, server, client) = proxied_setup(Transport::H2).await;

    let result = get_via_proxy_with_status(client.addr, &format!("{}/hello", origin.origin()));
    assert_eq!(result.status(), 200, "stdout={:?}", result.stdout);
    assert_eq!(result.stdout.lines().next(), Some("hello world"));
    assert!(server.context.stats.snapshot().streams_total >= 1);

    client.stop().await;
    server.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxies_https_connect_through_the_tunnel() {
    let tls_origin = TestTlsServer::start().await.unwrap();
    let key = test_psk();
    let server = RunningServer::start(&key, Transport::Tls).await;
    let client = RunningTunnelClient::start(
        &key,
        server.addr,
        &["CIDR,127.0.0.0/8"],
        Transport::Tls,
        "veilink.local",
    )
    .await;
    client.wait_ready(Duration::from_secs(15)).await;

    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("origin.pem");
    std::fs::write(&ca, tls_origin.certificate_pem()).unwrap();

    let result = veilink_testkit::curl::connect_tls_via_proxy(
        client.addr,
        "127.0.0.1",
        tls_origin.addr().port(),
        &ca,
        &[],
    );
    result.expect_ok("HTTPS through the tunnel");
    assert_eq!(result.stdout.lines().next(), Some("secure hello"));

    let client_stats = client.context.stats.snapshot();
    assert_eq!(client_stats.requests_proxied, 1);
    assert!(client_stats.bytes_up > 0 && client_stats.bytes_down > 0);
    assert!(client_stats.frames_sent > 0 && client_stats.frames_received > 0);

    client.stop().await;
    server.stop().await;
    tls_origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_download_survives_the_tunnel() {
    let (origin, server, client) = proxied_setup(Transport::Tls).await;
    const SIZE: usize = 2 * 1024 * 1024;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.bin");

    let written = veilink_testkit::curl::download_to_file(
        client.addr,
        &format!("{}/bytes?n={SIZE}", origin.origin()),
        &path,
    );
    assert_eq!(written as usize, SIZE);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        veilink_testkit::curl::expected_bytes(SIZE)
    );

    client.stop().await;
    server.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_streams_share_one_session() {
    let (origin, server, client) = proxied_setup(Transport::Tls).await;

    let mut tasks = Vec::new();
    for index in 0..12usize {
        let proxy = client.addr;
        let base = origin.origin();
        tasks.push(tokio::task::spawn_blocking(move || {
            let size = 512 * (index + 1);
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("f.bin");
            let written = veilink_testkit::curl::download_to_file(
                proxy,
                &format!("{base}/bytes?n={size}"),
                &path,
            );
            (size, written, std::fs::read(&path).unwrap())
        }));
    }
    for task in tasks {
        let (size, written, body) = task.await.unwrap();
        assert_eq!(written as usize, size);
        assert_eq!(body.len(), size);
    }

    let stats = client.context.stats.snapshot();
    assert_eq!(stats.requests_proxied, 12);
    // All twelve requests shared one outer connection.
    assert_eq!(stats.session_established, 1);
    assert_eq!(stats.session_connects, 1);

    client.stop().await;
    server.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_key_is_rejected_and_the_request_fails_closed() {
    let origin = TestServer::start().await.unwrap();
    let server_key = test_psk();
    let client_key = Psk::from_bytes(
        &(0u8..32)
            .map(|i| i.wrapping_mul(17).wrapping_add(5))
            .collect::<Vec<u8>>(),
    )
    .unwrap();

    let server = RunningServer::start(&server_key, Transport::Tls).await;
    let client = RunningTunnelClient::start(
        &client_key,
        server.addr,
        &["CIDR,127.0.0.0/8"],
        Transport::Tls,
        "veilink.local",
    )
    .await;

    // The session can never be established, so the request must be refused rather than downgraded.
    let result = get_via_proxy_with_status(client.addr, &format!("{}/hello", origin.origin()));
    assert_eq!(result.status(), 502, "stdout={:?}", result.stdout);
    assert_eq!(
        origin
            .stats()
            .connections
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the origin was contacted despite the whitelist"
    );
    assert!(server.context.stats.snapshot().auth_failures >= 1);
    assert!(client.context.stats.snapshot().session_failures >= 1);

    client.stop().await;
    server.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_routing_still_works_alongside_the_tunnel() {
    let (origin, server, client) = proxied_setup(Transport::Tls).await;

    // The whitelist only covers 127.0.0.0/8, so `localhost` is a domain target and goes DIRECT.
    let direct = get_via_proxy_with_host(
        client.addr,
        &format!("http://localhost:{}/hello", origin.addr().port()),
        "localhost",
    );
    direct.expect_ok("direct request");
    assert_eq!(direct.stdout, "hello world");

    // And the IP-literal form goes through the tunnel.
    let proxied = get_via_proxy_with_status(client.addr, &format!("{}/hello", origin.origin()));
    assert_eq!(proxied.status(), 200);

    let stats = client.context.stats.snapshot();
    assert_eq!(stats.requests_direct, 1);
    assert_eq!(stats.requests_proxied, 1);

    client.stop().await;
    server.stop().await;
    origin.stop().await;
}

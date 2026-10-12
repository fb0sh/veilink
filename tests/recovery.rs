//! Recovery behaviour: reconnection, fail-closed during an outage, and no downgrade.

use std::sync::atomic::Ordering;
use std::time::Duration;

use veilink_config::Transport;
use veilink_crypto::Psk;
use veilink_testkit::curl::get_via_proxy_with_status;
use veilink_testkit::settings::TEST_KEY;
use veilink_testkit::{RunningServer, RunningTunnelClient, TestServer};

fn test_psk() -> Psk {
    Psk::parse(TEST_KEY).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_fails_closed_while_the_server_is_down() {
    let origin = TestServer::start().await.unwrap();
    let key = test_psk();
    let server = RunningServer::start(&key, Transport::Tls).await;
    let server_addr = server.addr;
    let client = RunningTunnelClient::start(
        &key,
        server_addr,
        &["CIDR,127.0.0.0/8"],
        Transport::Tls,
        "veilink.local",
    )
    .await;
    client.wait_ready(Duration::from_secs(15)).await;

    // Stop the server: the session dies and the router must report the tunnel as unusable.
    server.stop().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let ready = client
            .context
            .router
            .load()
            .remote()
            .map(|t| t.is_ready())
            .unwrap_or(false);
        if !ready {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the client never noticed that the server went away"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // A whitelisted request must now be refused, and must never be sent directly.
    let before = origin.stats().connections.load(Ordering::Relaxed);
    let result = get_via_proxy_with_status(client.addr, &format!("{}/hello", origin.origin()));
    assert_eq!(result.status(), 502, "stdout={:?}", result.stdout);
    assert_eq!(
        origin.stats().connections.load(Ordering::Relaxed),
        before,
        "the request reached the origin directly after the tunnel failed"
    );

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_reconnects_when_the_server_returns() {
    let origin = TestServer::start().await.unwrap();
    let key = test_psk();
    let server = RunningServer::start(&key, Transport::Tls).await;
    let server_addr = server.addr;
    let client = RunningTunnelClient::start(
        &key,
        server_addr,
        &["CIDR,127.0.0.0/8"],
        Transport::Tls,
        "veilink.local",
    )
    .await;
    client.wait_ready(Duration::from_secs(15)).await;

    let first = get_via_proxy_with_status(client.addr, &format!("{}/hello", origin.origin()));
    assert_eq!(first.status(), 200);
    assert_eq!(client.context.stats.snapshot().session_established, 1);

    // Restart the server on the same port and wait for a second session.
    server.stop().await;
    let listener = tokio::net::TcpListener::bind(server_addr).await.unwrap();
    drop(listener);
    let server = RunningServer::start_at(&key, Transport::Tls, server_addr).await;

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let established = client.context.stats.snapshot().session_established;
        if established >= 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the client never re-established the session (established={established})"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Requests work again, through the new session.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let result = get_via_proxy_with_status(client.addr, &format!("{}/hello", origin.origin()));
        if result.status() == 200 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "requests did not recover after reconnection: {:?}",
            result.stdout
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    client.stop().await;
    server.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_server_is_reported_and_retried_with_backoff() {
    let key = test_psk();
    // Bind and drop so the address is certainly closed.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let client =
        RunningTunnelClient::start(&key, addr, &["*"], Transport::Tls, "veilink.local").await;

    // The uplink must keep trying rather than giving up or panicking.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let snapshot = client.context.stats.snapshot();
    assert!(
        snapshot.session_connects >= 2,
        "the uplink stopped retrying after {} attempt(s)",
        snapshot.session_connects
    );
    assert_eq!(snapshot.session_established, 0);
    assert!(!client
        .context
        .router
        .load()
        .remote()
        .map(|t| t.is_ready())
        .unwrap_or(false));

    client.stop().await;
}

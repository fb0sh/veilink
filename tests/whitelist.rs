//! Whitelist routing behaviour at the proxy boundary.
//!
//! The critical property is **fail-closed**: a request whose target matches the whitelist must go
//! through the tunnel, and if the tunnel is unavailable the request must fail. It must never be
//! quietly served by a direct connection, because that would contact — from the user's own
//! address — exactly the destination the user asked to reach through the VPS.

use std::sync::atomic::Ordering;

use veilink_testkit::curl::{get_via_proxy, get_via_proxy_with_status};
use veilink_testkit::settings::{client_settings_fast, RunningClient};
use veilink_testkit::TestServer;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unmatched_targets_go_direct() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&["DOMAIN-SUFFIX,example.com"])).await;

    let result = get_via_proxy(client.addr, &format!("{}/hello", origin.origin()));
    result.expect_ok("unmatched request must be served directly");
    assert_eq!(result.stdout, "hello world");
    assert_eq!(
        origin.stats().connections.load(Ordering::Relaxed),
        1,
        "the origin should have been contacted directly"
    );

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn matched_targets_never_fall_back_to_direct() {
    let origin = TestServer::start().await.unwrap();
    // `*` matches everything, including the IPv4 literal the origin is reached by. No tunnel is
    // configured, so the request must fail rather than reach the origin directly.
    let client = RunningClient::start(client_settings_fast(&["*"])).await;

    let result = get_via_proxy_with_status(client.addr, &format!("{}/hello", origin.origin()));
    // curl only fails on transport errors, so the status code is what proves the refusal.
    assert_eq!(
        result.status(),
        502,
        "expected a 502 refusal, got stdout={:?} stderr={:?}",
        result.stdout,
        result.stderr
    );
    assert_eq!(
        origin.stats().connections.load(Ordering::Relaxed),
        0,
        "the origin was contacted directly despite matching the whitelist"
    );
    assert_eq!(
        origin.stats().requests.load(Ordering::Relaxed),
        0,
        "the origin served a whitelisted request that should have been tunnelled"
    );

    let snapshot = client.context.stats.snapshot();
    assert_eq!(
        snapshot.requests_proxied, 1,
        "the request was not counted as PROXY"
    );
    assert_eq!(
        snapshot.requests_direct, 0,
        "the request was counted as DIRECT"
    );

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_never_falls_back_to_direct() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&["CIDR,127.0.0.0/8"])).await;

    let mut socket = tokio::net::TcpStream::connect(client.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let request = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        origin.addr(),
        origin.addr()
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    socket.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 502"),
        "expected a 502, got {text}"
    );
    assert_eq!(
        origin.stats().connections.load(Ordering::Relaxed),
        0,
        "CONNECT fell back to a direct connection"
    );

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn empty_whitelist_sends_everything_direct() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    for _ in 0..3 {
        let result = get_via_proxy(client.addr, &format!("{}/hello", origin.origin()));
        result.expect_ok("empty whitelist request");
    }
    let snapshot = client.context.stats.snapshot();
    assert_eq!(snapshot.requests_direct, 3);
    assert_eq!(snapshot.requests_proxied, 0);

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hot_reload_changes_routing_for_new_requests_only() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    // Everything is DIRECT to begin with.
    let first = get_via_proxy(client.addr, &format!("{}/hello", origin.origin()));
    first.expect_ok("initial direct request");
    assert_eq!(client.context.stats.snapshot().requests_direct, 1);

    // Reload with a catch-all rule. New requests must now be refused (no tunnel), and must not
    // reach the origin.
    let reloaded = veilink_testkit::settings::client_settings(&["*"]);
    client.context.set_rules(reloaded.rules.clone());

    let second = get_via_proxy_with_status(client.addr, &format!("{}/hello", origin.origin()));
    assert_eq!(
        second.status(),
        502,
        "the reloaded rule did not take effect: {:?}",
        second.stdout
    );
    let snapshot = client.context.stats.snapshot();
    assert_eq!(
        snapshot.requests_direct, 1,
        "routing did not change after the reload"
    );
    assert_eq!(snapshot.requests_proxied, 1);
    assert_eq!(
        origin.stats().connections.load(Ordering::Relaxed),
        1,
        "only the pre-reload request should have reached the origin"
    );

    // Reloading back to an empty whitelist restores DIRECT routing.
    let restored = veilink_testkit::settings::client_settings(&[]);
    client.context.set_rules(restored.rules.clone());
    let third = get_via_proxy(client.addr, &format!("{}/hello", origin.origin()));
    third.expect_ok("request after restoring the empty whitelist");

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rule_types_route_independently() {
    let origin = TestServer::start().await.unwrap();
    let address = origin.addr();
    let client = RunningClient::start(client_settings_fast(&[
        "DOMAIN-SUFFIX,example.com",
        &format!("IP,{}", address.ip()),
    ]))
    .await;

    // The origin is addressed by an IP literal that has an `IP` rule, so it must be PROXY-routed
    // and therefore refused.
    let result = get_via_proxy_with_status(client.addr, &format!("{}/hello", origin.origin()));
    assert_eq!(result.status(), 502, "an IP-rule match was not tunnelled");
    assert_eq!(origin.stats().connections.load(Ordering::Relaxed), 0);

    // `localhost` is a domain target with no matching domain rule, so it goes DIRECT.
    let direct = get_via_proxy(
        client.addr,
        &format!("http://localhost:{}/hello", address.port()),
    );
    direct.expect_ok("localhost must route DIRECT");
    assert_eq!(direct.stdout, "hello world");

    client.stop().await;
    origin.stop().await;
}

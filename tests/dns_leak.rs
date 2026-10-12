//! DNS privacy: proving that a whitelisted domain is resolved by the server and not by the client.

use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use veilink_config::Transport;
use veilink_crypto::Psk;
use veilink_testkit::curl::CurlResult;
use veilink_testkit::settings::TEST_KEY;
use veilink_testkit::{DnsStub, RunningServer, RunningTunnelClient, TestServer};

fn test_psk() -> Psk {
    Psk::parse(TEST_KEY).unwrap()
}

/// A name that only the server's resolver can resolve.
const PROBE: &str = "veilink-leak-probe.test";

/// Fetch `host:port` through the proxy, without letting curl resolve anything itself.
fn fetch(proxy: std::net::SocketAddr, host: &str, port: u16, path: &str) -> CurlResult {
    // `--resolve` is deliberately NOT used: the point is that the name must be resolved remotely.
    // curl is told the full URL, so it hands the proxy the name unresolved.
    veilink_testkit::curl::curl(&[
        "-x",
        &format!("http://{proxy}"),
        "-w",
        "\n%{http_code}",
        &format!("http://{host}:{port}{path}"),
    ])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_whitelisted_domain_is_resolved_remotely() {
    let origin = TestServer::start().await.unwrap();
    // The stub answers every name with the loopback address, which is where the origin lives.
    let stub = DnsStub::start(Ipv4Addr::LOCALHOST).await.unwrap();
    let key = test_psk();
    let server = RunningServer::start_with_dns(&key, Transport::Tls, Some(stub.addr())).await;
    let client = RunningTunnelClient::start(
        &key,
        server.addr,
        &[&format!("DOMAIN,{PROBE}")],
        Transport::Tls,
        "veilink.local",
    )
    .await;
    client.wait_ready(Duration::from_secs(15)).await;

    let result = fetch(client.addr, PROBE, origin.addr().port(), "/hello");
    assert_eq!(
        result.status(),
        200,
        "the server could not reach the target through its own resolver: {:?}",
        result.stdout
    );
    assert_eq!(result.stdout.lines().next(), Some("hello world"));

    // The server's resolver was asked exactly once for the probe name.
    assert_eq!(
        stub.count(PROBE),
        1,
        "the server did not resolve the name exactly once: {:?}",
        stub.queries()
    );
    // The request really did go through the tunnel.
    assert_eq!(client.context.stats.snapshot().requests_proxied, 1);
    assert!(server.context.stats.snapshot().streams_total >= 1);

    client.stop().await;
    server.stop().await;
    origin.stop().await;
    stub.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_request_never_uses_the_server_resolver() {
    let origin = TestServer::start().await.unwrap();
    let stub = DnsStub::start(Ipv4Addr::LOCALHOST).await.unwrap();
    let key = test_psk();
    let server = RunningServer::start_with_dns(&key, Transport::Tls, Some(stub.addr())).await;
    // The whitelist does not cover `localhost`, so it must be resolved locally.
    let client = RunningTunnelClient::start(
        &key,
        server.addr,
        &[&format!("DOMAIN,{PROBE}")],
        Transport::Tls,
        "veilink.local",
    )
    .await;
    client.wait_ready(Duration::from_secs(15)).await;

    let result = fetch(client.addr, "localhost", origin.addr().port(), "/hello");
    assert_eq!(result.status(), 200, "stdout={:?}", result.stdout);
    assert_eq!(client.context.stats.snapshot().requests_direct, 1);
    assert_eq!(
        stub.queries().len(),
        0,
        "a DIRECT request used the server's resolver: {:?}",
        stub.queries()
    );

    client.stop().await;
    server.stop().await;
    origin.stop().await;
    stub.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resolution_failure_on_a_whitelisted_name_does_not_fall_back() {
    let origin = TestServer::start().await.unwrap();
    // The stub resolves the probe to an address nothing is listening on.
    let stub = DnsStub::start(Ipv4Addr::new(127, 0, 0, 2)).await.unwrap();
    let key = test_psk();
    let server = RunningServer::start_with_dns(&key, Transport::Tls, Some(stub.addr())).await;
    let client = RunningTunnelClient::start(
        &key,
        server.addr,
        &[&format!("DOMAIN,{PROBE}")],
        Transport::Tls,
        "veilink.local",
    )
    .await;
    client.wait_ready(Duration::from_secs(15)).await;

    // The origin is on 127.0.0.1; the server resolves the probe to 127.0.0.2 where nothing listens,
    // so the stream must fail with 502 rather than being retried locally.
    let result = fetch(client.addr, PROBE, origin.addr().port(), "/hello");
    assert_eq!(result.status(), 502, "stdout={:?}", result.stdout);
    assert_eq!(
        origin.stats().connections.load(Ordering::Relaxed),
        0,
        "a failed remote resolution fell back to a local connection"
    );
    assert!(stub.count(PROBE) >= 1);

    client.stop().await;
    server.stop().await;
    origin.stop().await;
    stub.stop().await;
}

//! Concurrency and connection-lifecycle behaviour of the local proxy.
//!
//! These tests check that the listener keeps serving under load, that the connection cap is
//! enforced without dropping unrelated work, and that per-connection failures stay isolated.

use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use veilink_testkit::curl::{expected_bytes, get_via_proxy};
use veilink_testkit::settings::{client_settings_fast, RunningClient};
use veilink_testkit::TestServer;

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn serves_many_concurrent_requests() {
    const CONCURRENCY: usize = 32;
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    // Binary bodies must be compared as bytes, so each request writes to its own file.
    let dir = std::sync::Arc::new(tempfile::tempdir().unwrap());
    let mut tasks = Vec::with_capacity(CONCURRENCY);
    for index in 0..CONCURRENCY {
        let proxy = client.addr;
        let origin = origin.origin();
        let dir = dir.clone();
        tasks.push(tokio::task::spawn_blocking(move || {
            // Vary the size so that requests finish at different times.
            let size = 1024 * (index + 1);
            let path = dir.path().join(format!("r{index}.bin"));
            let result = veilink_testkit::curl::curl(&[
                "-x",
                &format!("http://{proxy}"),
                "-o",
                &path.display().to_string(),
                "-w",
                "%{size_download}",
                &format!("{origin}/bytes?n={size}"),
            ]);
            let got = std::fs::read(&path).unwrap_or_default();
            (index, size, result, got)
        }));
    }

    for task in tasks {
        let (index, size, result, got) = task.await.unwrap();
        result.expect_ok(&format!("concurrent request {index}"));
        assert_eq!(got.len(), size, "response {index} had the wrong length");
        assert_eq!(
            got,
            expected_bytes(size),
            "response {index} had altered contents"
        );
    }

    let snapshot = client.context.stats.snapshot();
    assert_eq!(snapshot.requests_direct as usize, CONCURRENCY);
    assert_eq!(snapshot.connections_active, 0, "connections leaked");

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interleaved_streams_do_not_mix_data() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;
    let dir = tempfile::tempdir().unwrap();

    // Two sizes with different contents running at the same time; each must arrive intact.
    let small = 64 * 1024;
    let large = 2 * 1024 * 1024;
    let small_path = dir.path().join("small.bin");
    let large_path = dir.path().join("large.bin");

    let proxy = client.addr;
    let small_url = format!("{}/bytes?n={small}", origin.origin());
    let large_url = format!("{}/bytes?n={large}", origin.origin());
    let small_out = small_path.clone();
    let large_out = large_path.clone();

    let small_task = tokio::task::spawn_blocking(move || {
        veilink_testkit::curl::download_to_file(proxy, &small_url, &small_out)
    });
    let large_task = tokio::task::spawn_blocking(move || {
        veilink_testkit::curl::download_to_file(proxy, &large_url, &large_out)
    });

    assert_eq!(small_task.await.unwrap() as usize, small);
    assert_eq!(large_task.await.unwrap() as usize, large);
    assert_eq!(std::fs::read(&small_path).unwrap(), expected_bytes(small));
    assert_eq!(std::fs::read(&large_path).unwrap(), expected_bytes(large));

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abrupt_client_disconnect_does_not_disturb_others() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    // Open a request and drop the socket mid-head.
    for _ in 0..8 {
        let mut socket = tokio::net::TcpStream::connect(client.addr).await.unwrap();
        socket.write_all(b"GET http://127.0.0.1/hel").await.unwrap();
        drop(socket);
    }
    // Open a connection and drop it with a partial head, then immediately do real work.
    let mut idle = tokio::net::TcpStream::connect(client.addr).await.unwrap();
    idle.write_all(b"CONNECT exa").await.unwrap();

    let result = get_via_proxy(client.addr, &format!("{}/hello", origin.origin()));
    result.expect_ok("request after abrupt disconnects");
    assert_eq!(result.stdout, "hello world");
    drop(idle);

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_connection_cap_refuses_excess_connections_without_failing() {
    let origin = TestServer::start().await.unwrap();
    let mut settings = client_settings_fast(&[]);
    settings.limits.max_connections = 4;
    let client = RunningClient::start(settings).await;

    // Hold four connections open by sending a partial head.
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut socket = tokio::net::TcpStream::connect(client.addr).await.unwrap();
        socket.write_all(b"GET http://127.0.0.1/").await.unwrap();
        held.push(socket);
    }
    tokio::time::sleep(Duration::from_millis(150)).await;

    // The fifth connection is accepted by the OS and then closed by the proxy.
    let mut extra = tokio::net::TcpStream::connect(client.addr).await.unwrap();
    extra
        .write_all(b"GET http://127.0.0.1/hello HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(3), extra.read(&mut buf))
        .await
        .expect("the refused connection was not closed");
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "excess connection was served"
    );

    // Releasing one slot lets new work through.
    held.pop();
    tokio::time::sleep(Duration::from_millis(150)).await;
    let result = get_via_proxy(client.addr, &format!("{}/hello", origin.origin()));
    result.expect_ok("request after a slot was released");

    drop(held);
    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_headers_are_rejected() {
    let client = RunningClient::start(client_settings_fast(&[])).await;
    let mut socket = tokio::net::TcpStream::connect(client.addr).await.unwrap();

    let mut request = String::from("GET http://127.0.0.1/hello HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    for index in 0..2000 {
        request.push_str(&format!("X-Pad-{index}: {}\r\n", "p".repeat(64)));
    }
    request.push_str("\r\n");
    let _ = socket.write_all(request.as_bytes()).await;

    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut response)).await;
    let text = String::from_utf8_lossy(&response);
    assert!(
        text.starts_with("HTTP/1.1 400"),
        "oversized headers were not rejected: {text}"
    );
    assert!(
        client.context.stats.snapshot().requests_rejected >= 1,
        "the rejection was not counted"
    );

    client.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn statistics_track_traffic() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    let size = 200 * 1024;
    // The `TempDir` must outlive the download, so it is bound rather than used inline.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.bin");
    let written = veilink_testkit::curl::download_to_file(
        client.addr,
        &format!("{}/bytes?n={size}", origin.origin()),
        &path,
    );
    assert_eq!(written as usize, size);

    let snapshot = client.context.stats.snapshot();
    assert_eq!(snapshot.connections_total, 1);
    assert_eq!(snapshot.requests_direct, 1);
    assert!(
        snapshot.bytes_down >= size as u64,
        "bytes_down was {} for a {size} byte body",
        snapshot.bytes_down
    );
    assert!(snapshot.bytes_up > 0, "bytes_up was not counted");
    assert!(origin.stats().bytes_out.load(Ordering::Relaxed) >= size as u64);

    client.stop().await;
    origin.stop().await;
}

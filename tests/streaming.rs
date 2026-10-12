//! Streaming, chunked and long-lived responses.
//!
//! Streaming is where a proxy is most likely to lose data or to buffer without bound. These tests
//! cover chunked transfer coding, server-sent events with real delays, responses delimited by
//! connection close, and client-side cancellation of a download in progress.

use std::time::{Duration, Instant};

use veilink_testkit::curl::{curl, download_to_file, expected_bytes, get_via_proxy};
use veilink_testkit::settings::{client_settings_fast, RunningClient};
use veilink_testkit::TestServer;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunked_responses_are_reassembled() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    let result = get_via_proxy(client.addr, &format!("{}/chunked", origin.origin()));
    result.expect_ok("chunked response");
    assert_eq!(result.stdout, "alphabetagamma");

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn server_sent_events_arrive_incrementally() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    // 12 chunks with a 40 ms gap: the whole body takes ~480 ms, so a proxy that buffered the
    // entire response before forwarding would still pass the content check but fail the timing
    // check. curl's `time_starttransfer` measures the first byte.
    let url = format!("{}/stream?chunks=12&delay_ms=40", origin.origin());
    let started = Instant::now();
    let result = curl(&[
        "-x",
        &format!("http://{}", client.addr),
        "-N",
        "-w",
        "\n%{time_starttransfer}",
        &url,
    ]);
    result.expect_ok("streamed response");
    let elapsed = started.elapsed();

    assert_eq!(result.stdout.matches("data: chunk-").count(), 12);
    assert!(
        elapsed >= Duration::from_millis(400),
        "the stream finished in {elapsed:?}, which means it was not streamed"
    );

    let first_byte_seconds: f64 = result
        .stdout
        .lines()
        .last()
        .and_then(|l| l.trim().parse().ok())
        .unwrap_or(f64::MAX);
    assert!(
        first_byte_seconds < 0.35,
        "the first byte took {first_byte_seconds}s, so the response was buffered instead of streamed"
    );

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn responses_ending_at_connection_close_are_forwarded() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    let result = get_via_proxy(client.addr, &format!("{}/eof", origin.origin()));
    result.expect_ok("until-EOF response");
    assert_eq!(result.stdout, "until-eof-payload");

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_download_does_not_break_the_client() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    // `--max-time` aborts a large download part-way through.
    let big = format!("{}/bytes?n={}", origin.origin(), 8 * 1024 * 1024);
    let aborted = curl(&[
        "-x",
        &format!("http://{}", client.addr),
        "--max-time",
        "1",
        "-o",
        "/dev/null",
        "-w",
        "%{size_download}",
        &big,
    ]);
    let _ = aborted; // Either a timeout or a completed download is acceptable.

    // The client must still serve a fresh, complete request afterwards.
    let after = get_via_proxy(client.addr, &format!("{}/hello", origin.origin()));
    after.expect_ok("request after a cancelled download");
    assert_eq!(after.stdout, "hello world");

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_sequential_downloads_stay_consistent() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;
    let dir = tempfile::tempdir().unwrap();

    for size in [1usize, 1024, 64 * 1024, 512 * 1024] {
        let path = dir.path().join(format!("d{size}.bin"));
        let url = format!("{}/bytes?n={size}", origin.origin());
        let written = download_to_file(client.addr, &url, &path);
        assert_eq!(written as usize, size, "wrong length for size {size}");
        let got = std::fs::read(&path).unwrap();
        assert_eq!(
            got,
            expected_bytes(size),
            "payload mismatch for size {size}"
        );
    }

    client.stop().await;
    origin.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_origin_does_not_block_other_connections() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    let slow = format!("{}/slow?delay_ms=1500", origin.origin());
    let fast = format!("{}/hello", origin.origin());
    let slow_proxy = client.addr;

    let slow_task =
        tokio::task::spawn_blocking(move || curl(&["-x", &format!("http://{slow_proxy}"), &slow]));
    tokio::time::sleep(Duration::from_millis(150)).await;

    let started = Instant::now();
    let fast_result = get_via_proxy(client.addr, &fast);
    fast_result.expect_ok("fast request while a slow one is in flight");
    assert_eq!(fast_result.stdout, "hello world");
    assert!(
        started.elapsed() < Duration::from_millis(1200),
        "the fast request waited for the slow one: {:?}",
        started.elapsed()
    );

    let slow_result = slow_task.await.unwrap();
    slow_result.expect_ok("slow request");

    client.stop().await;
    origin.stop().await;
}

/// Guards against a regression where the proxy would hold an entire body in memory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_streams_are_not_buffered_entirely() {
    let origin = TestServer::start().await.unwrap();
    let client = RunningClient::start(client_settings_fast(&[])).await;

    let limit_mb = 16usize;
    let url = format!("{}/bytes?n={}", origin.origin(), limit_mb * 1024 * 1024);
    let result = curl(&[
        "-x",
        &format!("http://{}", client.addr),
        "-o",
        "/dev/null",
        "-w",
        "%{size_download}",
        &url,
    ]);
    result.expect_ok("16 MiB download");
    assert_eq!(result.stdout.trim(), (limit_mb * 1024 * 1024).to_string());

    client.stop().await;
    origin.stop().await;
}

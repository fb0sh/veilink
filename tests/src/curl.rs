//! Thin wrappers around the `curl` binary.
//!
//! The acceptance criteria for Veilink are stated in terms of real client behaviour, so the tests
//! drive a real proxy client rather than a hand-rolled HTTP implementation. `curl` is used with
//! `--noproxy ""` so that the environment's own `no_proxy` settings cannot silently bypass Veilink.

use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};

/// The result of a curl invocation.
#[derive(Debug, Clone)]
pub struct CurlResult {
    /// Process exit code (`-1` when terminated by a signal).
    pub code: i32,
    /// Standard output, lossily decoded.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl CurlResult {
    /// True when curl exited successfully.
    pub fn ok(&self) -> bool {
        self.code == 0
    }

    /// Panics with the captured output when curl failed.
    pub fn expect_ok(&self, what: &str) -> &Self {
        assert!(
            self.ok(),
            "{what} failed with exit code {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code,
            self.stdout,
            self.stderr
        );
        self
    }

    /// The HTTP status code curl reported on the last stdout line, when requested with `-w`.
    pub fn status(&self) -> i32 {
        self.stdout
            .lines()
            .last()
            .and_then(|l| l.trim().parse().ok())
            .unwrap_or(0)
    }
}

/// Runs curl with the given arguments plus proxy-independent defaults.
pub fn curl(args: &[&str]) -> CurlResult {
    let output = Command::new("curl")
        .arg("--silent")
        .arg("--show-error")
        .arg("--noproxy")
        .arg("")
        .args(args)
        .output()
        .expect("curl must be installed to run the integration tests");
    CurlResult {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

fn proxy_arg(proxy: SocketAddr) -> String {
    format!("http://{proxy}")
}

/// Fetches `url` through the proxy, returning the body in `stdout`.
pub fn get_via_proxy(proxy: SocketAddr, url: &str) -> CurlResult {
    curl(&["-x", &proxy_arg(proxy), url])
}

/// Fetches `url` through the proxy, appending the HTTP status code on its own stdout line.
pub fn get_via_proxy_with_status(proxy: SocketAddr, url: &str) -> CurlResult {
    curl(&["-x", &proxy_arg(proxy), "-w", "\n%{http_code}", url])
}

/// Fetches `url` through the proxy with an explicit `Host` header override.
pub fn get_via_proxy_with_host(proxy: SocketAddr, url: &str, host: &str) -> CurlResult {
    curl(&["-x", &proxy_arg(proxy), "-H", &format!("Host: {host}"), url])
}

/// `CONNECT`s to `host:port` through the proxy and reports the final HTTP status code.
pub fn connect_via_proxy(proxy: SocketAddr, host: &str, port: u16) -> CurlResult {
    curl(&[
        "-x",
        &proxy_arg(proxy),
        "-p",
        "--connect-timeout",
        "5",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        &format!("https://{host}:{port}/"),
    ])
}

/// `CONNECT`s to a TLS origin through the proxy, trusting `ca_pem`.
pub fn connect_tls_via_proxy(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    ca_pem: &Path,
    extra: &[&str],
) -> CurlResult {
    let url = format!("https://{host}:{port}/");
    let mut args: Vec<String> = vec![
        "-x".into(),
        proxy_arg(proxy),
        "-p".into(),
        "--cacert".into(),
        ca_pem.display().to_string(),
        "--connect-timeout".into(),
        "10".into(),
        "-w".into(),
        "\n%{http_code}".into(),
    ];
    for item in extra {
        args.push((*item).to_string());
    }
    args.push(url);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    curl(&refs)
}

/// Uploads `body` with a `POST` request through the proxy.
pub fn post_via_proxy(proxy: SocketAddr, url: &str, body: &str) -> CurlResult {
    curl(&[
        "-x",
        &proxy_arg(proxy),
        "-X",
        "POST",
        "--data-binary",
        body,
        url,
    ])
}

/// Uploads `bytes` of generated data from standard input and returns the response body.
pub fn upload_from_stdin(proxy: SocketAddr, url: &str, bytes: usize) -> CurlResult {
    let mut child = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--noproxy",
            "",
            "-x",
            &proxy_arg(proxy),
            "-X",
            "POST",
            "--data-binary",
            "@-",
            url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("curl must be installed");
    {
        let stdin = child.stdin.as_mut().expect("curl stdin");
        let block: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        let mut written = 0usize;
        while written < bytes {
            let take = block.len().min(bytes - written);
            stdin.write_all(&block[..take]).expect("write to curl");
            written += take;
        }
    }
    let output = child.wait_with_output().expect("curl must finish");
    CurlResult {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// Downloads `url` through the proxy into `path`, returning the number of bytes written.
pub fn download_to_file(proxy: SocketAddr, url: &str, path: &Path) -> u64 {
    let result = curl(&[
        "-x",
        &proxy_arg(proxy),
        "-o",
        &path.display().to_string(),
        "-w",
        "%{size_download}",
        url,
    ]);
    result.expect_ok("download");
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// The deterministic payload produced by the test server's `/bytes` route.
pub fn expected_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

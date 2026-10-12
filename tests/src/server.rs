//! Test servers: a real HTTP/1.1 origin and a real TLS 1.3 origin.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

/// Counters exposed by the test servers so that tests can assert on observed behaviour.
#[derive(Debug, Default)]
pub struct ServerStats {
    /// Connections accepted.
    pub connections: AtomicU64,
    /// Requests handled.
    pub requests: AtomicU64,
    /// Bytes of request body read.
    pub bytes_in: AtomicU64,
    /// Bytes of response body written.
    pub bytes_out: AtomicU64,
    /// Host header values seen, in order.
    pub hosts: std::sync::Mutex<Vec<String>>,
}

impl ServerStats {
    /// Records a host name.
    pub fn record_host(&self, host: &str) {
        if let Ok(mut hosts) = self.hosts.lock() {
            hosts.push(host.to_string());
        }
    }

    /// The recorded host names.
    pub fn hosts(&self) -> Vec<String> {
        self.hosts.lock().map(|h| h.clone()).unwrap_or_default()
    }
}

/// A test HTTP/1.1 origin server.
pub struct TestServer {
    addr: SocketAddr,
    stats: Arc<ServerStats>,
    shutdown: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    /// Starts the server on an ephemeral loopback port.
    pub async fn start() -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let stats = Arc::new(ServerStats::default());
        let (tx, mut rx) = oneshot::channel();
        let task_stats = stats.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accepted = listener.accept() => {
                        let Ok((socket, _)) = accepted else { break };
                        task_stats.connections.fetch_add(1, Ordering::Relaxed);
                        let stats = task_stats.clone();
                        tokio::spawn(async move {
                            let _ = serve_connection(socket, stats).await;
                        });
                    }
                }
            }
        });
        Ok(TestServer {
            addr,
            stats,
            shutdown: Some(tx),
            handle,
        })
    }

    /// The listening address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:PORT`.
    pub fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Shared counters.
    pub fn stats(&self) -> Arc<ServerStats> {
        self.stats.clone()
    }

    /// Stops the server and waits for its accept loop to finish.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let handle = std::mem::replace(&mut self.handle, tokio::spawn(async {}));
        let _ = handle.await;
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn serve_connection(mut socket: TcpStream, stats: Arc<ServerStats>) -> io::Result<()> {
    socket.set_nodelay(true).ok();
    let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
    loop {
        // Read one request head.
        let head_len = loop {
            if let Some(pos) = find_head_end(&buf) {
                break pos;
            }
            let mut chunk = [0u8; 8192];
            let n = socket.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 256 * 1024 {
                return Ok(());
            }
        };
        let head = buf[..head_len].to_vec();
        buf.drain(..head_len);

        let request = match parse_request(&head) {
            Some(r) => r,
            None => {
                socket
                    .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await?;
                return Ok(());
            }
        };
        stats.requests.fetch_add(1, Ordering::Relaxed);
        if let Some(host) = request.header("host") {
            stats.record_host(&host);
        }

        // Read the request body according to its framing.
        let body = read_body(&mut socket, &mut buf, &request).await?;
        stats
            .bytes_in
            .fetch_add(body.len() as u64, Ordering::Relaxed);

        let keep_alive = request.keep_alive();
        let outcome = respond(&mut socket, &request, &body).await?;
        stats
            .bytes_out
            .fetch_add(outcome.written, Ordering::Relaxed);
        if !keep_alive || !outcome.keep_alive {
            return Ok(());
        }
    }
}

struct Outcome {
    written: u64,
    keep_alive: bool,
}

async fn respond(socket: &mut TcpStream, request: &Request, body: &[u8]) -> io::Result<Outcome> {
    let path = request.path.split('?').next().unwrap_or("");
    let query = Query::parse(&request.path);
    match path {
        "/hello" => {
            let payload = b"hello world";
            write_full(socket, 200, "OK", "text/plain", payload).await
        }
        "/echo" => write_full(socket, 200, "OK", "application/octet-stream", body).await,
        "/upload" => {
            let payload = format!("received:{}", body.len());
            write_full(socket, 200, "OK", "text/plain", payload.as_bytes()).await
        }
        "/bytes" => {
            let n: usize = query.get_usize("n").unwrap_or(1024).min(64 * 1024 * 1024);
            let payload: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            write_full(socket, 200, "OK", "application/octet-stream", &payload).await
        }
        "/status" => {
            let code = query.get_usize("code").unwrap_or(200) as u16;
            write_full(socket, code, "Status", "text/plain", b"status").await
        }
        "/chunked" => {
            let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n";
            socket.write_all(head).await?;
            let mut written = head.len() as u64;
            for piece in [&b"alpha"[..], b"beta", b"gamma"] {
                let line = format!("{:x}\r\n", piece.len());
                socket.write_all(line.as_bytes()).await?;
                socket.write_all(piece).await?;
                socket.write_all(b"\r\n").await?;
                written += line.len() as u64 + piece.len() as u64 + 2;
            }
            socket.write_all(b"0\r\n\r\n").await?;
            written += 5;
            socket.flush().await?;
            Ok(Outcome {
                written,
                keep_alive: true,
            })
        }
        "/stream" => {
            let chunks = query.get_usize("chunks").unwrap_or(5).min(200);
            let delay_ms = query.get_usize("delay_ms").unwrap_or(10).min(1000) as u64;
            let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                         Cache-Control: no-store\r\nTransfer-Encoding: chunked\r\n\r\n";
            socket.write_all(head).await?;
            let mut written = head.len() as u64;
            for i in 0..chunks {
                let piece = format!("data: chunk-{i}\n\n");
                let line = format!("{:x}\r\n", piece.len());
                socket.write_all(line.as_bytes()).await?;
                socket.write_all(piece.as_bytes()).await?;
                socket.write_all(b"\r\n").await?;
                written += line.len() as u64 + piece.len() as u64 + 2;
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            socket.write_all(b"0\r\n\r\n").await?;
            written += 5;
            socket.flush().await?;
            Ok(Outcome {
                written,
                keep_alive: true,
            })
        }
        "/eof" => {
            // No framing headers: the body ends when the connection does.
            let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
            socket.write_all(head).await?;
            socket.write_all(b"until-eof-payload").await?;
            socket.flush().await?;
            Ok(Outcome {
                written: (head.len() + 17) as u64,
                keep_alive: false,
            })
        }
        "/upgrade" => {
            let upgrade = request
                .header("upgrade")
                .unwrap_or_default()
                .to_ascii_lowercase();
            if upgrade != "websocket" {
                return write_full(socket, 400, "Bad Request", "text/plain", b"no upgrade").await;
            }
            let head = b"HTTP/1.1 101 Switching Protocols\r\n\
                         Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
            socket.write_all(head).await?;
            socket.flush().await?;
            // Echo raw bytes after the handshake, which is what a WebSocket peer would do.
            let mut written = head.len() as u64;
            let mut buf = [0u8; 4096];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        socket.write_all(&buf[..n]).await?;
                        written += n as u64;
                    }
                }
            }
            Ok(Outcome {
                written,
                keep_alive: false,
            })
        }
        "/slow" => {
            let delay_ms = query.get_usize("delay_ms").unwrap_or(50).min(5000) as u64;
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            write_full(socket, 200, "OK", "text/plain", b"slow").await
        }
        _ => write_full(socket, 404, "Not Found", "text/plain", b"not found").await,
    }
}

async fn write_full(
    socket: &mut TcpStream,
    status: u16,
    reason: &str,
    content_type: &str,
    payload: &[u8],
) -> io::Result<Outcome> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\n\r\n",
        payload.len()
    );
    socket.write_all(head.as_bytes()).await?;
    socket.write_all(payload).await?;
    socket.flush().await?;
    Ok(Outcome {
        written: (head.len() + payload.len()) as u64,
        keep_alive: true,
    })
}

/// A parsed test request.
#[derive(Debug, Clone)]
pub struct Request {
    /// Method.
    pub method: String,
    /// Request target as received.
    pub path: String,
    /// Version string, e.g. `HTTP/1.1`.
    pub version: String,
    /// Header fields, lower-cased names.
    pub headers: Vec<(String, String)>,
}

impl Request {
    /// Returns the first value of `name`.
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }

    /// Whether the connection should be reused.
    pub fn keep_alive(&self) -> bool {
        let connection = self
            .header("connection")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if connection.contains("close") {
            return false;
        }
        self.version == "HTTP/1.1" || connection.contains("keep-alive")
    }
}

fn parse_request(head: &[u8]) -> Option<Request> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    request.parse(head).ok()?;
    Some(Request {
        method: request.method?.to_string(),
        path: request.path?.to_string(),
        version: match request.version? {
            0 => "HTTP/1.0".to_string(),
            _ => "HTTP/1.1".to_string(),
        },
        headers: request
            .headers
            .iter()
            .map(|h| {
                (
                    h.name.to_ascii_lowercase(),
                    String::from_utf8_lossy(h.value).trim().to_string(),
                )
            })
            .collect(),
    })
}

async fn read_body(
    socket: &mut TcpStream,
    buf: &mut Vec<u8>,
    request: &Request,
) -> io::Result<Vec<u8>> {
    if let Some(te) = request.header("transfer-encoding") {
        if te.to_ascii_lowercase().contains("chunked") {
            return read_chunked(socket, buf).await;
        }
    }
    let Some(len) = request.header("content-length") else {
        return Ok(Vec::new());
    };
    let len: usize = len.trim().parse().unwrap_or(0);
    let mut body = Vec::with_capacity(len);
    while body.len() < len {
        if !buf.is_empty() {
            let take = buf.len().min(len - body.len());
            body.extend_from_slice(&buf[..take]);
            buf.drain(..take);
            continue;
        }
        let mut chunk = [0u8; 16 * 1024];
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(body)
}

async fn read_chunked(socket: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = read_line(socket, buf).await?;
        let size_text = String::from_utf8_lossy(&line);
        let size_text = size_text.trim();
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("0").trim(), 16)
            .unwrap_or(0);
        if size == 0 {
            // Consume trailers up to the blank line.
            loop {
                let trailer = read_line(socket, buf).await?;
                if trailer == b"\r\n" || trailer == b"\n" {
                    break;
                }
            }
            return Ok(body);
        }
        while buf.len() < size + 2 {
            let mut chunk = [0u8; 16 * 1024];
            let n = socket.read(&mut chunk).await?;
            if n == 0 {
                return Ok(body);
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        body.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2);
    }
}

async fn read_line(socket: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<Vec<u8>> {
    loop {
        if let Some(pos) = buf.iter().position(|b| *b == b'\n') {
            let line = buf[..=pos].to_vec();
            buf.drain(..=pos);
            return Ok(line);
        }
        let mut chunk = [0u8; 4096];
        let n = socket.read(&mut chunk).await?;
        if n == 0 {
            return Ok(std::mem::take(buf));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find_head_end(haystack: &[u8]) -> Option<usize> {
    let mut idx = 0usize;
    while idx < haystack.len() {
        if haystack[idx] == b'\n' {
            if idx + 1 < haystack.len() && haystack[idx + 1] == b'\n' {
                return Some(idx + 2);
            }
            if idx + 2 < haystack.len() && haystack[idx + 1] == b'\r' && haystack[idx + 2] == b'\n'
            {
                return Some(idx + 3);
            }
        }
        idx += 1;
    }
    None
}

/// A minimal query-string reader.
#[derive(Debug, Default)]
pub struct Query {
    pairs: Vec<(String, String)>,
}

impl Query {
    /// Parses the query string of a request target.
    pub fn parse(target: &str) -> Self {
        let mut pairs = Vec::new();
        if let Some((_, query)) = target.split_once('?') {
            for pair in query.split('&') {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                pairs.push((k.to_string(), v.to_string()));
            }
        }
        Query { pairs }
    }

    /// Returns a value by key.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Returns a numeric value by key.
    pub fn get_usize(&self, key: &str) -> Option<usize> {
        self.get(key)?.parse().ok()
    }
}

/// A real TLS 1.3 origin server with a generated certificate.
pub struct TestTlsServer {
    addr: SocketAddr,
    certificate_pem: String,
    stats: Arc<ServerStats>,
    shutdown: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<()>,
}

impl TestTlsServer {
    /// Starts a TLS server whose responses are served by the same routes as [`TestServer`].
    pub async fn start() -> io::Result<Self> {
        // The certificate carries both a DNS name and the loopback IP so that curl can verify it
        // whichever way the test addresses the origin.
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .map_err(io::Error::other)?;
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(std::net::IpAddr::from([
                127, 0, 0, 1,
            ])));
        let key_pair = rcgen::KeyPair::generate().map_err(io::Error::other)?;
        let cert = params.self_signed(&key_pair).map_err(io::Error::other)?;
        let certificate_pem = cert.pem();
        let cert_der = cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
        );

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(io::Error::other)?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let stats = Arc::new(ServerStats::default());
        let (tx, mut rx) = oneshot::channel();
        let task_stats = stats.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    accepted = listener.accept() => {
                        let Ok((socket, _)) = accepted else { break };
                        task_stats.connections.fetch_add(1, Ordering::Relaxed);
                        let acceptor = acceptor.clone();
                        let stats = task_stats.clone();
                        tokio::spawn(async move {
                            if let Ok(tls) = acceptor.accept(socket).await {
                                let mut stream = tls;
                                let _ = serve_tls_connection(&mut stream, stats).await;
                            }
                        });
                    }
                }
            }
        });
        Ok(TestTlsServer {
            addr,
            certificate_pem,
            stats,
            shutdown: Some(tx),
            handle,
        })
    }

    /// The listening address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// PEM certificate, for `curl --cacert`.
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// Shared counters.
    pub fn stats(&self) -> Arc<ServerStats> {
        self.stats.clone()
    }

    /// Stops the server and waits for its accept loop to finish.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let handle = std::mem::replace(&mut self.handle, tokio::spawn(async {}));
        let _ = handle.await;
    }
}

impl Drop for TestTlsServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn serve_tls_connection<S>(socket: &mut S, stats: Arc<ServerStats>) -> io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    loop {
        let head_len = loop {
            if let Some(pos) = find_head_end(&buf) {
                break pos;
            }
            let mut chunk = [0u8; 8192];
            let n = socket.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let head = buf[..head_len].to_vec();
        buf.drain(..head_len);
        let Some(request) = parse_request(&head) else {
            return Ok(());
        };
        stats.requests.fetch_add(1, Ordering::Relaxed);
        if let Some(host) = request.header("host") {
            stats.record_host(&host);
        }
        let keep_alive = request.keep_alive();
        let body = b"secure hello".to_vec();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        socket.write_all(head.as_bytes()).await?;
        socket.write_all(&body).await?;
        socket.flush().await?;
        if !keep_alive {
            return Ok(());
        }
    }
}

//! HTTP/1.1 message parsing, framing and rewriting.
//!
//! Veilink is a byte-level forward proxy: it parses exactly as much of each message as is needed to
//! keep the connection framing in sync, and forwards everything else verbatim. That is what makes
//! `CONNECT` tunnelling, `Upgrade`, chunked streaming and long-lived server-sent events behave
//! identically to a direct connection.

use std::fmt;
use std::io;

use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

use veilink_protocol::duplex::{BufStream, Duplex, MAX_LINE_BYTES};

/// Maximum number of header fields accepted in one message.
pub const MAX_HEADERS: usize = 128;

/// Maximum length of a request target we are willing to parse.
pub const MAX_TARGET_BYTES: usize = 8 * 1024;

/// Maximum length of an authority (host:port).
pub const MAX_AUTHORITY_BYTES: usize = 512;

/// Errors raised while parsing or framing an HTTP/1.1 message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// The request head could not be parsed.
    #[error("malformed HTTP request: {0}")]
    MalformedRequest(String),
    /// The response head could not be parsed.
    #[error("malformed HTTP response: {0}")]
    MalformedResponse(String),
    /// The authority could not be determined or is invalid.
    #[error("invalid request authority: {0}")]
    BadAuthority(String),
    /// The request target exceeded [`MAX_TARGET_BYTES`].
    #[error("request target is longer than {MAX_TARGET_BYTES} bytes")]
    TargetTooLong,
    /// A transfer coding other than `chunked` was requested.
    #[error("unsupported transfer coding `{0}`")]
    UnsupportedTransferEncoding(String),
    /// The HTTP version is not supported.
    #[error("unsupported HTTP version `{0}`; only HTTP/1.0 and HTTP/1.1 are proxied")]
    UnsupportedVersion(String),
    /// Two different `Content-Length` values were present.
    #[error("conflicting Content-Length values")]
    ConflictingContentLength,
    /// The `Content-Length` value was not a non-negative integer.
    #[error("invalid Content-Length `{0}`")]
    InvalidContentLength(String),
}

impl HttpError {
    /// The HTTP status code that best describes this error when answering a client.
    pub fn status(&self) -> u16 {
        match self {
            HttpError::MalformedRequest(_)
            | HttpError::BadAuthority(_)
            | HttpError::ConflictingContentLength
            | HttpError::InvalidContentLength(_) => 400,
            HttpError::TargetTooLong => 414,
            HttpError::UnsupportedTransferEncoding(_) => 501,
            HttpError::UnsupportedVersion(_) => 505,
            HttpError::MalformedResponse(_) => 502,
        }
    }
}

/// A parsed block of header fields, preserving original bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderBlock {
    /// Fields in the order they appeared.
    pub fields: Vec<(Vec<u8>, Vec<u8>)>,
}

impl HeaderBlock {
    /// Returns the value of the first field named `name` (case-insensitive).
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| v.as_slice())
    }

    /// Returns every value for `name`.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.fields
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name.as_bytes()))
            .map(|(_, v)| v.as_slice())
    }

    /// True when a field named `name` exists.
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Removes every field named `name`.
    pub fn remove(&mut self, name: &str) {
        self.fields
            .retain(|(k, _)| !k.eq_ignore_ascii_case(name.as_bytes()));
    }

    /// Returns the comma-separated tokens of the first `name` field, lower-cased.
    fn tokens(&self, name: &str) -> Vec<String> {
        let mut out = Vec::new();
        for value in self.get_all(name) {
            for part in value.split(|b| *b == b',') {
                let token = String::from_utf8_lossy(part).trim().to_ascii_lowercase();
                if !token.is_empty() {
                    out.push(token);
                }
            }
        }
        out
    }
}

/// A parsed HTTP/1.x request head.
#[derive(Debug, Clone)]
pub struct RequestHead {
    /// Method, as received.
    pub method: Vec<u8>,
    /// Request target, as received (absolute-form, origin-form or authority-form).
    pub target: Vec<u8>,
    /// `0` for HTTP/1.0, `1` for HTTP/1.1.
    pub version: u8,
    /// Header fields.
    pub headers: HeaderBlock,
}

/// A parsed HTTP/1.x response head.
#[derive(Debug, Clone)]
pub struct ResponseHead {
    /// `0` for HTTP/1.0, `1` for HTTP/1.1.
    pub version: u8,
    /// Status code.
    pub status: u16,
    /// Reason phrase, possibly empty.
    pub reason: Vec<u8>,
    /// Header fields.
    pub headers: HeaderBlock,
}

/// The authority a request is addressed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    /// Host name or IPv4 literal exactly as written by the client.
    pub host: String,
    /// Destination port.
    pub port: u16,
}

impl fmt::Display for Authority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// How the body of a message is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body follows.
    None,
    /// Exactly this many bytes follow.
    Length(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// The body runs until the peer closes the connection.
    UntilEof,
}

/// Parses a request head from the raw bytes returned by
/// [`BufStream::read_head`](veilink_protocol::duplex::BufStream::read_head).
pub fn parse_request_head(raw: &[u8]) -> Result<RequestHead, HttpError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(raw) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => {
            return Err(HttpError::MalformedRequest(
                "header block is incomplete".to_string(),
            ))
        }
        Err(e) => return Err(HttpError::MalformedRequest(e.to_string())),
    }

    let method = request
        .method
        .ok_or_else(|| HttpError::MalformedRequest("missing method".to_string()))?
        .as_bytes()
        .to_vec();
    let target = request
        .path
        .ok_or_else(|| HttpError::MalformedRequest("missing request target".to_string()))?
        .as_bytes()
        .to_vec();
    if target.len() > MAX_TARGET_BYTES {
        return Err(HttpError::TargetTooLong);
    }
    let version = match request.version {
        Some(v) => v,
        None => {
            return Err(HttpError::MalformedRequest(
                "missing HTTP version".to_string(),
            ))
        }
    };
    if version > 1 {
        return Err(HttpError::UnsupportedVersion(format!("HTTP/1.{version}")));
    }

    let mut block = HeaderBlock::default();
    for header in request.headers.iter() {
        if header.name.is_empty() {
            continue;
        }
        block
            .fields
            .push((header.name.as_bytes().to_vec(), header.value.to_vec()));
    }

    Ok(RequestHead {
        method,
        target,
        version,
        headers: block,
    })
}

/// Parses a response head.
pub fn parse_response_head(raw: &[u8]) -> Result<ResponseHead, HttpError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(raw) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => {
            return Err(HttpError::MalformedResponse(
                "header block is incomplete".to_string(),
            ))
        }
        Err(e) => return Err(HttpError::MalformedResponse(e.to_string())),
    }
    let status = response
        .code
        .ok_or_else(|| HttpError::MalformedResponse("missing status code".to_string()))?;
    let version = response.version.unwrap_or(1);
    if version > 1 {
        return Err(HttpError::UnsupportedVersion(format!("HTTP/1.{version}")));
    }
    let mut block = HeaderBlock::default();
    for header in response.headers.iter() {
        if header.name.is_empty() {
            continue;
        }
        block
            .fields
            .push((header.name.as_bytes().to_vec(), header.value.to_vec()));
    }
    Ok(ResponseHead {
        version,
        status,
        reason: response.reason.unwrap_or("").as_bytes().to_vec(),
        headers: block,
    })
}

impl RequestHead {
    /// The upper-case method as a string.
    pub fn method_str(&self) -> String {
        String::from_utf8_lossy(&self.method).to_ascii_uppercase()
    }

    /// True when this is a `CONNECT` request.
    pub fn is_connect(&self) -> bool {
        self.method.eq_ignore_ascii_case(b"CONNECT")
    }

    /// True when the head requests a protocol upgrade (used for WebSocket).
    pub fn is_upgrade_request(&self) -> bool {
        let connection_upgrade = self
            .headers
            .tokens("connection")
            .iter()
            .any(|t| t == "upgrade");
        connection_upgrade && self.headers.contains("upgrade")
    }

    /// True when the connection should be kept open after this message.
    pub fn is_keep_alive(&self) -> bool {
        is_keep_alive(self.version, &self.headers)
    }

    /// Resolves the destination authority.
    pub fn authority(&self) -> Result<Authority, HttpError> {
        if self.is_connect() {
            let text = std::str::from_utf8(&self.target).map_err(|_| {
                HttpError::BadAuthority("CONNECT target is not valid ASCII".to_string())
            })?;
            let (host, port) = crate::routing::split_host_port(text, 443)?;
            return Ok(Authority { host, port });
        }

        let target = std::str::from_utf8(&self.target).map_err(|_| {
            HttpError::BadAuthority("request target is not valid ASCII".to_string())
        })?;

        if let Some(rest) = strip_scheme(target) {
            // absolute-form: `http://host[:port]/path`
            let (authority, _path) = split_authority_and_path(rest);
            if authority.is_empty() {
                return Err(HttpError::BadAuthority(format!("`{target}` has no host")));
            }
            let default_port = default_port_for(target);
            let (host, port) = crate::routing::split_host_port(authority, default_port)?;
            return Ok(Authority { host, port });
        }

        if target == "*" {
            // `OPTIONS *` carries no authority; fall back to the Host header.
            return self.authority_from_host_header(80);
        }

        self.authority_from_host_header(80)
    }

    fn authority_from_host_header(&self, default_port: u16) -> Result<Authority, HttpError> {
        let host = self.headers.get("host").ok_or_else(|| {
            HttpError::BadAuthority(
                "request has neither an absolute target nor a Host header".into(),
            )
        })?;
        let host = std::str::from_utf8(host)
            .map_err(|_| HttpError::BadAuthority("Host header is not valid ASCII".to_string()))?;
        let host = host.trim();
        if host.is_empty() {
            return Err(HttpError::BadAuthority("Host header is empty".to_string()));
        }
        let (host, port) = crate::routing::split_host_port(host, default_port)?;
        Ok(Authority { host, port })
    }

    /// The origin-form target to send upstream: path and query only.
    pub fn origin_form(&self) -> String {
        let target = String::from_utf8_lossy(&self.target);
        if self.is_connect() {
            return target.to_string();
        }
        if let Some(rest) = strip_scheme(&target) {
            let (_authority, path) = split_authority_and_path(rest);
            if path.is_empty() {
                return "/".to_string();
            }
            return path.to_string();
        }
        if target.is_empty() {
            "/".to_string()
        } else {
            target.to_string()
        }
    }

    /// Determines how the request body is delimited.
    pub fn body_framing(&self) -> Result<BodyFraming, HttpError> {
        request_framing(&self.headers)
    }

    /// Serialises the request for the upstream server, dropping hop-by-hop fields.
    ///
    /// The `Host` header is preserved if present and synthesised otherwise, so that upstream always
    /// sees a well-formed HTTP/1.1 request.
    pub fn serialize_for_upstream(&self, authority: &Authority) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.method);
        out.push(b' ');
        out.extend_from_slice(self.origin_form().as_bytes());
        out.extend_from_slice(b" HTTP/1.1\r\n");

        // A protocol upgrade is the one case where the hop-by-hop headers must be forwarded:
        // the origin cannot answer `101` unless it sees `Connection: Upgrade` and `Upgrade`.
        let upgrading = self.is_upgrade_request();
        let connection_tokens = self.headers.tokens("connection");
        let mut wrote_host = false;
        for (name, value) in &self.headers.fields {
            let lower = name.to_ascii_lowercase();
            let lower = String::from_utf8_lossy(&lower);
            if upgrading && (lower == "upgrade" || lower == "connection") {
                out.extend_from_slice(name);
                out.extend_from_slice(b": ");
                out.extend_from_slice(value);
                out.extend_from_slice(b"\r\n");
                continue;
            }
            // Hop-by-hop headers must not be forwarded (RFC 9110 §7.6.1).
            if matches!(
                lower.as_ref(),
                "connection"
                    | "proxy-connection"
                    | "keep-alive"
                    | "proxy-authenticate"
                    | "proxy-authorization"
            ) {
                continue;
            }
            if lower != "upgrade" && connection_tokens.iter().any(|t| t == lower.as_ref()) {
                continue;
            }
            if lower == "host" {
                // Preserve the client's Host header byte for byte: it may carry an explicit port
                // or a name that does not round-trip through our own formatting.
                wrote_host = true;
                out.extend_from_slice(name);
                out.extend_from_slice(b": ");
                out.extend_from_slice(value);
                out.extend_from_slice(b"\r\n");
                continue;
            }
            out.extend_from_slice(name);
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        if !wrote_host {
            out.extend_from_slice(b"Host: ");
            out.extend_from_slice(authority.host.as_bytes());
            out.push(b':');
            out.extend_from_slice(authority.port.to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out
    }
}

impl ResponseHead {
    /// True when the connection may be reused after this response.
    pub fn is_keep_alive(&self) -> bool {
        is_keep_alive(self.version, &self.headers)
    }

    /// True when the response is an `Upgrade` acceptance.
    pub fn is_switching_protocols(&self) -> bool {
        self.status == 101
    }

    /// Serialises the response for the client, dropping proxy-specific fields.
    pub fn serialize_for_client(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(if self.version == 0 {
            b"HTTP/1.0 "
        } else {
            b"HTTP/1.1 "
        });
        out.extend_from_slice(self.status.to_string().as_bytes());
        if !self.reason.is_empty() {
            out.push(b' ');
            out.extend_from_slice(&self.reason);
        }
        out.extend_from_slice(b"\r\n");
        for (name, value) in &self.headers.fields {
            if name.eq_ignore_ascii_case(b"proxy-authenticate")
                || name.eq_ignore_ascii_case(b"proxy-connection")
            {
                continue;
            }
            out.extend_from_slice(name);
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out
    }

    /// Determines how the response body is delimited.
    pub fn body_framing(&self, request_method: &[u8]) -> Result<BodyFraming, HttpError> {
        response_framing(self, request_method)
    }
}

/// `true` when a connection with this version and headers should be reused.
fn is_keep_alive(version: u8, headers: &HeaderBlock) -> bool {
    let tokens = {
        let mut tokens: Vec<String> = Vec::new();
        for value in headers.get_all("connection") {
            for part in value.split(|b| *b == b',') {
                let token = String::from_utf8_lossy(part).trim().to_ascii_lowercase();
                if !token.is_empty() {
                    tokens.push(token);
                }
            }
        }
        tokens
    };
    if tokens.iter().any(|t| t == "close") {
        return false;
    }
    if version == 1 {
        return true;
    }
    tokens.iter().any(|t| t == "keep-alive")
}

/// Frames a request body.
fn request_framing(headers: &HeaderBlock) -> Result<BodyFraming, HttpError> {
    if let Some(te) = headers.get("transfer-encoding") {
        let value = String::from_utf8_lossy(te).to_ascii_lowercase();
        let codings: Vec<&str> = value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        // Only `chunked` is understood, and it must be the final coding.
        if codings.last() == Some(&"chunked") {
            return Ok(BodyFraming::Chunked);
        }
        return Err(HttpError::UnsupportedTransferEncoding(value));
    }
    match content_length(headers)? {
        Some(len) => Ok(BodyFraming::Length(len)),
        None => Ok(BodyFraming::None),
    }
}

/// Frames a response body, which also depends on the request method.
fn response_framing(head: &ResponseHead, request_method: &[u8]) -> Result<BodyFraming, HttpError> {
    // These never carry a body, whatever the headers claim.
    if request_method.eq_ignore_ascii_case(b"HEAD")
        || head.status == 204
        || head.status == 304
        || (100..200).contains(&head.status)
    {
        return Ok(BodyFraming::None);
    }
    if let Some(te) = head.headers.get("transfer-encoding") {
        let value = String::from_utf8_lossy(te).to_ascii_lowercase();
        let codings: Vec<&str> = value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        return match codings.last() {
            Some(&"chunked") => Ok(BodyFraming::Chunked),
            _ => Err(HttpError::UnsupportedTransferEncoding(value)),
        };
    }
    match content_length(&head.headers)? {
        Some(len) => Ok(BodyFraming::Length(len)),
        None => Ok(BodyFraming::UntilEof),
    }
}

/// Extracts and validates `Content-Length`.
fn content_length(headers: &HeaderBlock) -> Result<Option<u64>, HttpError> {
    let mut seen: Option<u64> = None;
    for value in headers.get_all("content-length") {
        let text = String::from_utf8_lossy(value);
        // A single field may itself be a comma-separated list of identical values.
        for part in text.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let parsed: u64 = part
                .parse()
                .map_err(|_| HttpError::InvalidContentLength(part.to_string()))?;
            match seen {
                Some(existing) if existing != parsed => {
                    return Err(HttpError::ConflictingContentLength)
                }
                _ => seen = Some(parsed),
            }
        }
    }
    Ok(seen)
}

/// Returns the substring after `scheme://`, if the target is absolute-form.
fn strip_scheme(target: &str) -> Option<&str> {
    let idx = target.find("://")?;
    let scheme = &target[..idx];
    if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
        Some(&target[idx + 3..])
    } else {
        None
    }
}

fn default_port_for(target: &str) -> u16 {
    if target.len() >= 5 && target[..5].eq_ignore_ascii_case("https") {
        443
    } else {
        80
    }
}

fn split_authority_and_path(rest: &str) -> (&str, &str) {
    match rest.find(['/', '?', '#']) {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    }
}

/// Forwards a chunked body from `src` to `dst`, rewriting nothing.
///
/// Returns the number of payload bytes forwarded (framing excluded).
pub async fn forward_chunked<S, W>(src: &mut BufStream<S>, dst: &mut W) -> io::Result<u64>
where
    S: Duplex,
    W: AsyncWrite + Unpin,
{
    let mut payload = 0u64;
    loop {
        let line = src.read_line(MAX_LINE_BYTES).await?;
        let size = parse_chunk_size(&line).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed chunk size in chunked body",
            )
        })?;
        dst.write_all(&line).await?;
        if size == 0 {
            // Trailer section: zero or more fields, terminated by an empty line.
            loop {
                let trailer = src.read_line(MAX_LINE_BYTES).await?;
                let empty = trailer == b"\r\n" || trailer == b"\n";
                dst.write_all(&trailer).await?;
                if empty {
                    dst.flush().await?;
                    return Ok(payload);
                }
            }
        }
        src.forward_exact(dst, size + 2).await?;
        payload += size;
    }
}

/// Parses the hexadecimal length from a chunk-size line, ignoring extensions.
fn parse_chunk_size(line: &[u8]) -> Option<u64> {
    let mut end = 0usize;
    while end < line.len() && line[end] != b';' && line[end] != b'\r' && line[end] != b'\n' {
        end += 1;
    }
    let digits = std::str::from_utf8(&line[..end]).ok()?.trim();
    if digits.is_empty() || digits.len() > 16 {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

/// Writes a minimal HTTP error response to `dst`.
pub async fn write_error_response<W>(
    dst: &mut W,
    status: u16,
    reason: &str,
    detail: &str,
    close: bool,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let body = format!("{status} {reason}\n{detail}\n");
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: {}\r\n\
         \r\n",
        body.len(),
        if close { "close" } else { "keep-alive" }
    );
    dst.write_all(head.as_bytes()).await?;
    dst.write_all(body.as_bytes()).await?;
    dst.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(raw: &str) -> RequestHead {
        parse_request_head(raw.as_bytes()).unwrap()
    }

    #[test]
    fn parses_absolute_form_and_resolves_authority() {
        let head = req("GET http://example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\n\r\n");
        let authority = head.authority().unwrap();
        assert_eq!(authority.host, "example.com");
        assert_eq!(authority.port, 80);
        assert_eq!(head.origin_form(), "/a?b=1");
    }

    #[test]
    fn absolute_form_https_defaults_to_443() {
        let head = req("GET https://example.com/ HTTP/1.1\r\n\r\n");
        assert_eq!(head.authority().unwrap().port, 443);
    }

    #[test]
    fn absolute_form_with_explicit_port() {
        let head = req("GET http://example.com:8080/x HTTP/1.1\r\n\r\n");
        let authority = head.authority().unwrap();
        assert_eq!(authority.host, "example.com");
        assert_eq!(authority.port, 8080);
    }

    #[test]
    fn origin_form_uses_host_header() {
        let head = req("GET /x HTTP/1.1\r\nHost: example.com:8080\r\n\r\n");
        let authority = head.authority().unwrap();
        assert_eq!(authority.host, "example.com");
        assert_eq!(authority.port, 8080);

        let head = req("GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assert_eq!(head.authority().unwrap().port, 80);
    }

    #[test]
    fn connect_uses_authority_form() {
        let head = req("CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n");
        assert!(head.is_connect());
        let authority = head.authority().unwrap();
        assert_eq!(authority.host, "github.com");
        assert_eq!(authority.port, 443);
    }

    #[test]
    fn connect_without_port_defaults_to_443() {
        let head = req("CONNECT github.com HTTP/1.1\r\n\r\n");
        assert_eq!(head.authority().unwrap().port, 443);
    }

    #[test]
    fn missing_authority_is_an_error() {
        let head = req("GET /x HTTP/1.1\r\n\r\n");
        let err = head.authority().unwrap_err();
        assert_eq!(err.status(), 400);
    }

    #[test]
    fn strips_hop_by_hop_headers_on_serialise() {
        let head = req("GET http://example.com/ HTTP/1.1\r\n\
             Host: example.com\r\n\
             Proxy-Connection: keep-alive\r\n\
             Connection: keep-alive, X-Drop-Me\r\n\
             X-Drop-Me: 1\r\n\
             Keep-Me: 2\r\n\
             Proxy-Authorization: Basic zzz\r\n\
             \r\n");
        let serialized =
            String::from_utf8(head.serialize_for_upstream(&head.authority().unwrap())).unwrap();
        assert!(serialized.starts_with("GET / HTTP/1.1\r\n"));
        assert!(!serialized.to_lowercase().contains("proxy-connection"));
        assert!(!serialized.to_lowercase().contains("proxy-authorization"));
        assert!(!serialized.contains("X-Drop-Me"));
        assert!(!serialized.to_lowercase().contains("connection:"));
        assert!(serialized.contains("Keep-Me: 2"));
        assert!(serialized.contains("Host: example.com\r\n"));
    }

    #[test]
    fn synthesises_host_when_absent() {
        let head = req("GET http://example.com/a HTTP/1.1\r\n\r\n");
        let serialized =
            String::from_utf8(head.serialize_for_upstream(&head.authority().unwrap())).unwrap();
        assert!(
            serialized.contains("Host: example.com:80\r\n"),
            "{serialized}"
        );
    }

    #[test]
    fn keep_alive_semantics() {
        assert!(req("GET / HTTP/1.1\r\nHost: a\r\n\r\n").is_keep_alive());
        assert!(!req("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").is_keep_alive());
        assert!(!req("GET / HTTP/1.0\r\nHost: a\r\n\r\n").is_keep_alive());
        assert!(req("GET / HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n").is_keep_alive());
    }

    #[test]
    fn upgrade_detection() {
        let head =
            req("GET /ws HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
        assert!(head.is_upgrade_request());
        let plain = req("GET / HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\n\r\n");
        assert!(!plain.is_upgrade_request());
    }

    #[test]
    fn request_body_framing() {
        assert_eq!(
            req("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n")
                .body_framing()
                .unwrap(),
            BodyFraming::Length(5)
        );
        assert_eq!(
            req("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n")
                .body_framing()
                .unwrap(),
            BodyFraming::Chunked
        );
        assert_eq!(
            req("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
                .body_framing()
                .unwrap(),
            BodyFraming::None
        );
    }

    #[test]
    fn conflicting_content_length_is_rejected() {
        let head =
            req("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n");
        assert_eq!(
            head.body_framing().unwrap_err(),
            HttpError::ConflictingContentLength
        );
    }

    #[test]
    fn duplicate_identical_content_length_is_accepted() {
        let head =
            req("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n");
        assert_eq!(head.body_framing().unwrap(), BodyFraming::Length(5));
    }

    #[test]
    fn unsupported_transfer_coding_is_rejected() {
        let head = req("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n");
        assert!(matches!(
            head.body_framing().unwrap_err(),
            HttpError::UnsupportedTransferEncoding(_)
        ));
    }

    #[test]
    fn response_framing_rules() {
        let head = parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n").unwrap();
        assert_eq!(head.body_framing(b"GET").unwrap(), BodyFraming::Length(3));

        let head = parse_response_head(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        assert_eq!(head.body_framing(b"GET").unwrap(), BodyFraming::UntilEof);

        let head = parse_response_head(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert_eq!(head.body_framing(b"GET").unwrap(), BodyFraming::None);

        let head = parse_response_head(b"HTTP/1.1 304 Not Modified\r\n\r\n").unwrap();
        assert_eq!(head.body_framing(b"GET").unwrap(), BodyFraming::None);

        // A HEAD response never has a body even with a Content-Length.
        let head = parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n").unwrap();
        assert_eq!(head.body_framing(b"HEAD").unwrap(), BodyFraming::None);

        let head =
            parse_response_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        assert_eq!(head.body_framing(b"GET").unwrap(), BodyFraming::Chunked);
    }

    #[test]
    fn response_serialisation_drops_proxy_headers() {
        let head = parse_response_head(
            b"HTTP/1.1 200 OK\r\nProxy-Authenticate: Basic\r\nX-Keep: 1\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();
        let text = String::from_utf8(head.serialize_for_client()).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(!text.contains("Proxy-Authenticate"));
        assert!(text.contains("X-Keep: 1"));
    }

    #[test]
    fn chunk_size_parsing() {
        assert_eq!(parse_chunk_size(b"5\r\n"), Some(5));
        assert_eq!(parse_chunk_size(b"1a;ext=1\r\n"), Some(26));
        assert_eq!(parse_chunk_size(b"0\r\n"), Some(0));
        assert_eq!(parse_chunk_size(b"zz\r\n"), None);
        assert_eq!(parse_chunk_size(b"\r\n"), None);
    }

    #[tokio::test]
    async fn forwards_chunked_body_verbatim() {
        use tokio::io::duplex;
        let (mut a, b) = duplex(4096);
        let mut src = BufStream::new(b);
        a.write_all(b"5\r\nhello\r\n6;x=1\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\nNEXT")
            .await
            .unwrap();
        let (mut r, mut w) = duplex(4096);
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut r, &mut got)
                .await
                .unwrap();
            got
        });
        let payload = forward_chunked(&mut src, &mut w).await.unwrap();
        drop(w);
        assert_eq!(payload, 11);
        assert_eq!(
            reader.await.unwrap(),
            b"5\r\nhello\r\n6;x=1\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n"
        );
        // The next pipelined message is untouched.
        assert_eq!(src.buffered(), b"NEXT");
    }

    #[tokio::test]
    async fn rejects_malformed_chunk() {
        use tokio::io::duplex;
        let (mut a, b) = duplex(1024);
        let mut src = BufStream::new(b);
        a.write_all(b"zz\r\n").await.unwrap();
        let (mut _r, mut w) = duplex(1024);
        let err = forward_chunked(&mut src, &mut w).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn writes_error_response() {
        let (mut r, mut w) = tokio::io::duplex(1024);
        write_error_response(&mut w, 502, "Bad Gateway", "upstream refused", true)
            .await
            .unwrap();
        drop(w);
        let mut got = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut r, &mut got)
            .await
            .unwrap();
        let text = String::from_utf8(got).unwrap();
        assert!(text.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
        assert!(text.contains("Connection: close"));
    }
}

//! The HTTP/1.1 forward proxy connection handler.
//!
//! One task serves one client connection. For each request it:
//!
//! 1. reads and parses the request head with a bounded header budget;
//! 2. resolves the destination authority;
//! 3. evaluates the whitelist and selects `DIRECT` or `PROXY`;
//! 4. obtains a byte pipe to the target (local `TcpStream` or tunnel stream);
//! 5. forwards the head, the body and the response, keeping the framing in sync;
//! 6. keeps the connection open for the next request when both sides allow it.
//!
//! `CONNECT` is handled separately: the request head is consumed, a pipe is opened, `200 Connection
//! Established` is returned, and the connection becomes a raw byte splice. Nothing in the TLS
//! handshake or the HTTPS payload is inspected or modified.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use veilink_rules::Decision;

use crate::http::{
    forward_chunked, parse_request_head, parse_response_head, write_error_response, BodyFraming,
    HttpError,
};
use crate::routing::{RouteError, RouteSelection, RouteTarget};
use crate::runtime::ClientContext;
use veilink_protocol::duplex::{BoxStream, BufStream};

/// Result of serving one client connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionOutcome {
    /// The client closed the connection between requests.
    ClientClosed,
    /// The client sent `Connection: close`, or the response required closing.
    ClosedByPolicy,
    /// A protocol error ended the connection.
    ProtocolError,
}

/// Serves a single accepted client connection until it ends.
pub async fn serve(socket: TcpStream, ctx: Arc<ClientContext>) -> ConnectionOutcome {
    socket.set_nodelay(true).ok();
    let started = Instant::now();
    let max_head = ctx.limits.max_header_bytes;
    let idle = Duration::from_millis(ctx.limits.idle_timeout_ms);

    let mut client = BufStream::with_limit(socket, max_head + 64 * 1024);
    let mut upstream: Option<Upstream> = None;

    loop {
        let head_raw = match tokio::time::timeout(idle, client.read_head(max_head)).await {
            Err(_) => {
                debug!("client connection idle timeout");
                return ConnectionOutcome::ClientClosed;
            }
            Ok(Err(e)) => {
                debug!(error = %e, "failed to read request head");
                ctx.stats.inc(&ctx.stats.requests_rejected);
                let _ = write_error_response(
                    client.inner_mut(),
                    400,
                    "Bad Request",
                    &format!("could not read request: {e}"),
                    true,
                )
                .await;
                return ConnectionOutcome::ProtocolError;
            }
            Ok(Ok(None)) => {
                debug!(
                    elapsed_ms = started.elapsed().as_millis(),
                    "client closed connection"
                );
                return ConnectionOutcome::ClientClosed;
            }
            Ok(Ok(Some(raw))) => raw,
        };

        let head = match parse_request_head(&head_raw) {
            Ok(head) => head,
            Err(e) => {
                ctx.stats.inc(&ctx.stats.requests_rejected);
                warn!(error = %e, "rejecting malformed request");
                let _ = write_error_response(
                    client.inner_mut(),
                    e.status(),
                    "Bad Request",
                    &e.to_string(),
                    true,
                )
                .await;
                return ConnectionOutcome::ProtocolError;
            }
        };

        if head.is_connect() {
            return handle_connect(client, &head, &ctx).await;
        }

        let mut head_sent = false;
        match handle_forward(&mut client, &head, &mut upstream, &ctx, &mut head_sent).await {
            Ok(ForwardOutcome::KeepAlive) => continue,
            Ok(ForwardOutcome::Close) => {
                // Half-close before dropping the socket. Dropping a socket that still has unread
                // data queued makes the kernel send an RST, which can truncate a response that ends
                // at connection close; an explicit FIN lets the client read to the end.
                let _ = client.shutdown_write().await;
                return ConnectionOutcome::ClosedByPolicy;
            }
            Ok(ForwardOutcome::Hijacked) => return ConnectionOutcome::ClosedByPolicy,
            Err(e) => {
                debug!(error = %e, head_sent, "proxy error");
                if !head_sent {
                    // Nothing of the response has been written yet, so the client can still be told
                    // what went wrong instead of seeing an empty reply.
                    ctx.stats.inc(&ctx.stats.requests_rejected);
                    let _ = write_error_response(
                        client.inner_mut(),
                        e.status(),
                        e.reason(),
                        &e.to_string(),
                        true,
                    )
                    .await;
                }
                let _ = client.shutdown_write().await;
                return ConnectionOutcome::ProtocolError;
            }
        }
    }
}

/// A cached upstream connection.
struct Upstream {
    key: UpstreamKey,
    stream: BufStream<BoxStream>,
    /// Set when the upstream response forbade reuse or the framing consumed the stream.
    poisoned: bool,
}

/// Identity of an upstream connection for reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UpstreamKey {
    host: String,
    port: u16,
    route: &'static str,
}

/// The outcome of forwarding one request/response exchange.
enum ForwardOutcome {
    /// The connection can serve another request.
    KeepAlive,
    /// The connection must be closed.
    Close,
    /// The connection became a raw tunnel.
    Hijacked,
}

async fn handle_forward(
    client: &mut BufStream<TcpStream>,
    head: &crate::http::RequestHead,
    upstream: &mut Option<Upstream>,
    ctx: &Arc<ClientContext>,
    head_sent: &mut bool,
) -> Result<ForwardOutcome, ProxyError> {
    let authority = head.authority()?;
    let route_target = RouteTarget::new(authority)?;
    let selection = {
        let rules = ctx.rules.snapshot();
        let decision: Decision = rules.decide(&route_target.target);
        RouteSelection::from_decision(&decision)
    };

    ctx.count_route(&selection);
    if ctx.log_domains {
        info!(
            route = selection.label(),
            host = route_target.transmit_host(),
            port = route_target.authority.port,
            method = %head.method_str(),
            "request"
        );
    } else {
        info!(
            route = selection.label(),
            target = route_target.target.describe(false),
            port = route_target.authority.port,
            method = %head.method_str(),
            "request"
        );
    }

    let key = UpstreamKey {
        host: route_target.transmit_host().to_string(),
        port: route_target.authority.port,
        route: selection.label(),
    };

    // Validate the request framing before touching the network so that a malformed request is
    // rejected without opening an outbound connection.
    let request_framing = head.body_framing()?;

    // `Expect: 100-continue` is answered locally. Waiting for the origin server instead would
    // deadlock: the client would not send its body until it saw `100`, and we would not read the
    // origin's response until the body was forwarded.
    let mut expect_continue = false;
    for value in head.headers.get_all("expect") {
        let token = String::from_utf8_lossy(value).trim().to_ascii_lowercase();
        if token == "100-continue" {
            expect_continue = true;
        } else if !token.is_empty() {
            ctx.stats.inc(&ctx.stats.requests_rejected);
            write_error_response(
                client.inner_mut(),
                417,
                "Expectation Failed",
                &format!("unsupported expectation `{token}`"),
                true,
            )
            .await?;
            return Ok(ForwardOutcome::Close);
        }
    }
    if expect_continue {
        client
            .inner_mut()
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await?;
        client.inner_mut().flush().await?;
    }

    // Reuse the upstream connection when it addresses the same target over the same route.
    let reusable = upstream
        .as_ref()
        .map(|u| !u.poisoned && u.key == key)
        .unwrap_or(false);
    if !reusable {
        *upstream = None;
    }
    if upstream.is_none() {
        let stream = ctx
            .router
            .load()
            .open(&selection, &key.host, key.port)
            .await?;
        *upstream = Some(Upstream {
            key: key.clone(),
            stream: BufStream::with_limit(stream, 256 * 1024),
            poisoned: false,
        });
    }
    let up = upstream.as_mut().expect("upstream is present");

    // Forward the request head (with `Expect` removed, since we already answered it) and then the
    // body, so that the origin never waits for a `100` of its own.
    let mut forwarded_head = head.clone();
    if expect_continue {
        forwarded_head.headers.remove("expect");
    }
    let head_bytes = forwarded_head.serialize_for_upstream(&route_target.authority);
    up.stream.write_all(&head_bytes).await?;
    up.stream.flush().await?;
    ctx.stats.add(&ctx.stats.bytes_up, head_bytes.len() as u64);

    match request_framing {
        BodyFraming::None => {}
        BodyFraming::Length(n) => {
            client.forward_exact(up.stream.inner_mut(), n).await?;
            ctx.stats.add(&ctx.stats.bytes_up, n);
        }
        BodyFraming::Chunked => {
            let payload = forward_chunked(client, up.stream.inner_mut()).await?;
            ctx.stats.add(&ctx.stats.bytes_up, payload);
        }
        BodyFraming::UntilEof => {
            let copied = client.forward_until_eof(up.stream.inner_mut()).await?;
            ctx.stats.add(&ctx.stats.bytes_up, copied);
            // A request body delimited by EOF means the client is done sending; the upstream
            // connection cannot be reused afterwards.
            up.poisoned = true;
        }
    }

    // Read the response, forwarding any informational responses first.
    let response = loop {
        let raw = up.stream.read_head(ctx.limits.max_header_bytes).await?;
        let raw = match raw {
            Some(raw) => raw,
            None => {
                // The origin closed without answering.
                write_error_response(
                    client.inner_mut(),
                    502,
                    "Bad Gateway",
                    "upstream closed the connection without sending a response",
                    true,
                )
                .await?;
                return Ok(ForwardOutcome::Close);
            }
        };
        let parsed = match parse_response_head(&raw) {
            Ok(parsed) => parsed,
            Err(e) => {
                up.poisoned = true;
                write_error_response(
                    client.inner_mut(),
                    502,
                    "Bad Gateway",
                    &format!("upstream sent a malformed response: {e}"),
                    true,
                )
                .await?;
                return Ok(ForwardOutcome::Close);
            }
        };
        if (100..200).contains(&parsed.status) && parsed.status != 101 {
            // 1xx responses carry no body and must be relayed immediately.
            debug!(status = parsed.status, "relaying informational response");
            client
                .inner_mut()
                .write_all(&parsed.serialize_for_client())
                .await?;
            client.inner_mut().flush().await?;
            continue;
        }
        break parsed;
    };

    let upgrading = response.is_switching_protocols() && head.is_upgrade_request();
    let response_framing = if upgrading {
        BodyFraming::None
    } else {
        response.body_framing(&head.method)?
    };

    let head_bytes = response.serialize_for_client();
    client.inner_mut().write_all(&head_bytes).await?;
    client.inner_mut().flush().await?;
    // From here on the response is committed: an error can only close the connection.
    *head_sent = true;

    if upgrading {
        info!("connection upgraded; switching to a raw byte splice");
        let mut upstream_stream = upstream.take().expect("upstream is present").stream;
        let outcome = veilink_protocol::duplex::splice(client, &mut upstream_stream).await?;
        ctx.stats.add(&ctx.stats.bytes_up, outcome.a_to_b);
        ctx.stats.add(&ctx.stats.bytes_down, outcome.b_to_a);
        return Ok(ForwardOutcome::Hijacked);
    }

    match response_framing {
        BodyFraming::None => {}
        BodyFraming::Length(n) => {
            up.stream.forward_exact(client.inner_mut(), n).await?;
            ctx.stats.add(&ctx.stats.bytes_down, n);
        }
        BodyFraming::Chunked => {
            let payload = forward_chunked(&mut up.stream, client.inner_mut()).await?;
            ctx.stats.add(&ctx.stats.bytes_down, payload);
        }
        BodyFraming::UntilEof => {
            let copied = up.stream.forward_until_eof(client.inner_mut()).await?;
            ctx.stats.add(&ctx.stats.bytes_down, copied);
            // The origin ended the body by closing; nothing can be reused and the client has
            // necessarily seen the end of the message too.
            up.poisoned = true;
            return Ok(ForwardOutcome::Close);
        }
    }

    let upstream_keep_alive = response.is_keep_alive() && !up.poisoned;
    if !upstream_keep_alive {
        *upstream = None;
    }
    let client_keep_alive = head.is_keep_alive() && upstream_keep_alive;
    Ok(if client_keep_alive {
        ForwardOutcome::KeepAlive
    } else {
        ForwardOutcome::Close
    })
}

async fn handle_connect(
    mut client: BufStream<TcpStream>,
    head: &crate::http::RequestHead,
    ctx: &Arc<ClientContext>,
) -> ConnectionOutcome {
    let started = Instant::now();
    let authority = match head.authority() {
        Ok(a) => a,
        Err(e) => {
            ctx.stats.inc(&ctx.stats.requests_rejected);
            let _ =
                write_error_response(client.inner_mut(), 400, "Bad Request", &e.to_string(), true)
                    .await;
            return ConnectionOutcome::ProtocolError;
        }
    };
    let route_target = match RouteTarget::new(authority) {
        Ok(t) => t,
        Err(e) => {
            ctx.stats.inc(&ctx.stats.requests_rejected);
            let _ =
                write_error_response(client.inner_mut(), 400, "Bad Request", &e.to_string(), true)
                    .await;
            return ConnectionOutcome::ProtocolError;
        }
    };
    let selection = {
        let rules = ctx.rules.snapshot();
        RouteSelection::from_decision(&rules.decide(&route_target.target))
    };
    ctx.count_route(&selection);

    if ctx.log_domains {
        info!(
            route = selection.label(),
            host = route_target.transmit_host(),
            port = route_target.authority.port,
            "CONNECT"
        );
    } else {
        info!(
            route = selection.label(),
            target = route_target.target.describe(false),
            port = route_target.authority.port,
            "CONNECT"
        );
    }

    let stream = match ctx
        .router
        .load()
        .open(
            &selection,
            route_target.transmit_host(),
            route_target.authority.port,
        )
        .await
    {
        Ok(stream) => stream,
        Err(e) => {
            ctx.stats.inc(&ctx.stats.requests_rejected);
            // Fail closed: the client is told the tunnel could not be established. It is never
            // connected directly instead.
            warn!(error = %e, route = selection.label(), "CONNECT failed");
            let _ = write_error_response(
                client.inner_mut(),
                502,
                "Bad Gateway",
                &format!("cannot establish a connection to the requested host: {e}"),
                true,
            )
            .await;
            return ConnectionOutcome::ProtocolError;
        }
    };

    if let Err(e) = client
        .inner_mut()
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
    {
        debug!(error = %e, "failed to acknowledge CONNECT");
        return ConnectionOutcome::ProtocolError;
    }
    if let Err(e) = client.inner_mut().flush().await {
        debug!(error = %e, "failed to flush CONNECT acknowledgement");
        return ConnectionOutcome::ProtocolError;
    }

    let mut upstream = Upstream {
        key: UpstreamKey {
            host: route_target.transmit_host().to_string(),
            port: route_target.authority.port,
            route: selection.label(),
        },
        stream: BufStream::with_limit(stream, 256 * 1024),
        poisoned: false,
    };
    match veilink_protocol::duplex::splice(&mut client, &mut upstream.stream).await {
        Ok(outcome) => {
            ctx.stats.add(&ctx.stats.bytes_up, outcome.a_to_b);
            ctx.stats.add(&ctx.stats.bytes_down, outcome.b_to_a);
        }
        Err(e) => debug!(error = %e, "tunnel ended with an error"),
    }
    debug!(
        elapsed_ms = started.elapsed().as_millis(),
        "CONNECT tunnel finished"
    );
    ConnectionOutcome::ClosedByPolicy
}

/// Errors raised by the proxy loop.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    /// An I/O error while talking to the client or the origin.
    #[error("I/O error: {0}")]
    Client(#[from] std::io::Error),
    /// The request was malformed.
    #[error(transparent)]
    Http(#[from] HttpError),
    /// The target could not be routed.
    #[error(transparent)]
    Route(#[from] RouteError),
}

impl ProxyError {
    /// The HTTP status code to report when the failure happened before the response was committed.
    pub fn status(&self) -> u16 {
        match self {
            ProxyError::Http(e) => e.status(),
            // A whitelisted target that cannot be tunnelled is a gateway failure, not a bad
            // request: the client did nothing wrong, the tunnel is unavailable.
            ProxyError::Route(RouteError::TunnelUnavailable { .. })
            | ProxyError::Route(RouteError::TunnelConnect { .. }) => 502,
            ProxyError::Route(_) => 400,
            ProxyError::Client(e) => match e.kind() {
                std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => 400,
                _ => 502,
            },
        }
    }

    /// The reason phrase matching [`ProxyError::status`].
    pub fn reason(&self) -> &'static str {
        match self.status() {
            400 => "Bad Request",
            414 => "URI Too Long",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            505 => "HTTP Version Not Supported",
            _ => "Bad Request",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_keys_compare_by_target_and_route() {
        let a = UpstreamKey {
            host: "example.com".into(),
            port: 80,
            route: "DIRECT",
        };
        let b = UpstreamKey {
            host: "example.com".into(),
            port: 80,
            route: "DIRECT",
        };
        let c = UpstreamKey {
            host: "example.com".into(),
            port: 80,
            route: "PROXY",
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn proxy_error_status_mapping_is_stable() {
        let http: HttpError = HttpError::TargetTooLong;
        assert_eq!(http.status(), 414);
        let proxy: ProxyError = http.into();
        assert!(proxy.to_string().contains("request target"));
    }
}

//! # veilink-client
//!
//! The local half of Veilink: an HTTP/1.1 forward proxy that decides, per request, whether traffic
//! is forwarded through the remote Veilink server or connected directly.
//!
//! ## What it does
//!
//! * Listens on `127.0.0.1:7890` by default and speaks ordinary HTTP proxy to local applications,
//!   so `curl -x http://127.0.0.1:7890 ...`, browsers and `git` work without configuration beyond
//!   pointing them at the proxy.
//! * Handles absolute-form requests, origin-form requests and `CONNECT`, plus `Upgrade` (WebSocket)
//!   and chunked or streamed bodies.
//! * Evaluates the whitelist against the destination and routes the request `DIRECT` (local TCP,
//!   system resolver) or `PROXY` (through the encrypted tunnel, remote resolver).
//! * Never downgrades: a request that matched the whitelist fails if the tunnel is unavailable,
//!   rather than silently connecting directly.
//!
//! ## What it does not do
//!
//! * It does not terminate TLS. `CONNECT` tunnels are raw byte pipes; the client never sees
//!   plaintext for an HTTPS destination.
//! * It does not pre-resolve whitelisted domain names. A domain that matches the whitelist is
//!   passed to the server unresolved, so the local resolver never learns about it.
//!
//! ## Layout
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`duplex`] | buffered duplex stream and byte-accounted forwarding (from `veilink-protocol`) |
//! | [`http`] | HTTP/1.1 parsing, framing and head rewriting |
//! | [`routing`] | authority parsing and Direct/Proxy selection |
//! | [`tunnel`] | the `Tunnel` abstraction and fail-closed route selection |
//! | [`proxy`] | the per-connection request/response handler |
//! | [`runtime`] | listener, limits and shared context |
//! | [`stats`] | runtime counters (from `veilink-protocol`) |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod http;
pub mod proxy;
pub mod routing;
pub mod runtime;
pub mod tunnel;
pub mod uplink;

pub use routing::{RouteError, RouteSelection, RouteTarget};
pub use runtime::{ClientContext, ClientRuntime};
pub use tunnel::{DirectTunnel, Router, Tunnel};
pub use veilink_protocol::duplex::{self, BoxStream, BufStream, Duplex, SpliceOutcome};
pub use veilink_protocol::stats::{self, Stats, StatsSnapshot};

/// The default local proxy address, mirroring [`veilink_config::DEFAULT_CLIENT_LISTEN`].
pub const DEFAULT_LISTEN: &str = veilink_config::DEFAULT_CLIENT_LISTEN;

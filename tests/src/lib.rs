//! Shared harness for the Veilink integration tests.
//!
//! The harness provides three things:
//!
//! * [`server::TestServer`] — a real TCP HTTP/1.1 server with routes for keep-alive, chunked
//!   bodies, streamed responses, large uploads and WebSocket upgrades;
//! * [`server::TestTlsServer`] — the same idea behind a real TLS 1.3 listener with a generated
//!   certificate, so `CONNECT` is exercised against genuine TLS rather than a byte echo;
//! * [`curl`] — thin wrappers around the `curl` binary, because the acceptance criteria are stated
//!   in terms of real client behaviour and curl is the most faithful stand-in for a browser.

#![forbid(unsafe_code)]

pub mod curl;
pub mod server;
pub mod settings;

pub use server::{TestServer, TestTlsServer};

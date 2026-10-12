//! # veilink-transport
//!
//! How Veilink's two peers reach each other.
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`tls`] | TLS 1.3 configuration, the generated server identity, and the PSK-bound certificate policy |
//! | [`connector`] | connecting and accepting, plus extraction of the TLS exporter used for channel binding |
//! | [`http2`] | carrying the `VLP/1` byte stream inside one HTTP/2 request/response body pair |
//!
//! ## The authentication story in one place
//!
//! The server presents a self-signed certificate that the client does not validate through a
//! certificate authority. That is safe *only* because the `VLP/1` handshake authenticates both
//! peers with the pre-shared key and binds that authentication to the live TLS session via the TLS
//! exporter. See [`tls`] for the full argument, including the residual risks.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod connector;
pub mod http2;
pub mod tls;

pub use connector::{
    accept, accept_expecting, acceptor, acceptor_for, connect, connect_expecting, connect_with,
    AcceptedConnection, ExporterSource, SecureConnection,
};
pub use tls::{
    check_alpn, client_config, client_config_for, install_crypto_provider, server_config,
    server_config_for, PskBoundVerifier, ServerTlsIdentity, TlsError, ALPN_H2, ALPN_VLP,
};

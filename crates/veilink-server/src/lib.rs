//! # veilink-server
//!
//! The remote half of Veilink.
//!
//! The server terminates the authenticated `VLP/1` session, resolves target names *remotely*, and
//! opens the outbound IPv4 connections the client asked for. Two properties define its security
//! posture:
//!
//! * **Authentication is mandatory.** No proxy request is read before the `PSK`-bound handshake has
//!   completed, and an authentication failure closes the connection immediately. There is no
//!   unauthenticated mode and no fallback.
//! * **Egress is constrained.** Every destination is checked against [`policy::EgressPolicy`] after
//!   resolution, and the socket is opened against the checked address, so neither special-use
//!   ranges nor a rebinding DNS answer can be used to reach the VPS's own network.
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`resolver`] | IPv4-only DNS with TTL cache, timeouts and retries |
//! | [`policy`] | special-use address and destination-port denial |
//! | [`egress`] | resolve, authorise, connect and splice |
//!
//! The session layer (TLS 1.3, the `VLP/1` framing and the per-frame cryptography) is built on top
//! of these modules and lives in `veilink-transport` and `veilink-protocol`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod egress;
pub mod policy;
pub mod resolver;

pub use egress::{Egress, EgressError};
pub use policy::{EgressPolicy, PolicyDeny};
pub use resolver::{ResolveError, Resolver};

//! # veilink-privacy
//!
//! The Strict Privacy layer: the mechanisms that reduce how much a passive observer can learn from
//! traffic *shape*, as opposed to traffic *content*.
//!
//! | Module | Concern |
//! |--------|---------|
//! | [`padding`] | hide payload length by rounding to fixed buckets |
//! | [`scheduler`] | remove the fine timing structure that mirrors application behaviour |
//! | [`cover`] | keep a session from being conspicuously silent |
//! | [`budget`] | make sure none of the above can become a denial of service or a bandwidth bill |
//!
//! ## What this layer does not do
//!
//! It does not make Veilink undetectable, anonymous or unlinkable. The outer connection still
//! reveals the server's address and port, the TLS handshake, when traffic starts and stops, how many
//! frames were exchanged, the bucket-sized lengths, and the fact that Veilink is being used at all.
//! See `docs/privacy.md`.
//!
//! ## Always on
//!
//! Every mechanism here is enabled by default and is not configurable through the YAML files. The
//! parameters are internal constants chosen for a reasonable bandwidth, latency and cost trade-off.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod budget;
pub mod cover;
pub mod padding;
pub mod scheduler;

pub use budget::{Budget, BudgetError, BudgetTracker};
pub use cover::{
    ActivityClock, CoverConfig, CoverEngine, CoverSink, CoverSnapshot, CoverStats, SessionCoverSink,
};
pub use padding::BudgetedPadding;
pub use scheduler::{PrivacyScheduler, SchedulerConfig};

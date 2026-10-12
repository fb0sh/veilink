//! `tracing` initialisation shared by the client and the server.

use anyhow::{Context, Result};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use veilink_config::{LogConfig, LogFormat};

/// Options controlling subscriber setup.
#[derive(Debug, Clone)]
pub struct InitOptions {
    /// Log configuration from the configuration file.
    pub config: LogConfig,
    /// Default level used when neither the configuration nor `RUST_LOG` sets one.
    pub default_level: &'static str,
}

impl Default for InitOptions {
    fn default() -> Self {
        InitOptions {
            config: LogConfig::default(),
            default_level: "info",
        }
    }
}

/// Initialises the global tracing subscriber.
///
/// `RUST_LOG` always wins over the configuration file, which keeps ad-hoc debugging possible
/// without editing YAML. Returns an error only if a subscriber is already installed.
pub fn init(options: InitOptions) -> Result<()> {
    let InitOptions {
        config,
        default_level,
    } = options;

    // `RUST_LOG` first, then the configured level, then the built-in default.
    let builder = EnvFilter::builder();
    let filter = match std::env::var("RUST_LOG") {
        Ok(value) if !value.trim().is_empty() => builder.parse_lossy(value),
        _ => match config.level.as_deref() {
            Some(level) if !level.trim().is_empty() => builder.parse_lossy(level),
            _ => builder.parse_lossy(default_level),
        },
    };

    // `LocalTime` requires the `time` feature; the default UTC timestamp format is used instead.
    let registry = tracing_subscriber::registry().with(filter);
    match config.format {
        LogFormat::Json => registry
            .with(
                fmt::layer()
                    .json()
                    .with_current_span(false)
                    .with_span_list(false)
                    .with_target(true),
            )
            .try_init()
            .context("failed to install the global tracing subscriber")?,
        LogFormat::Text => registry
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_level(true)
                    .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr())),
            )
            .try_init()
            .context("failed to install the global tracing subscriber")?,
    }
    Ok(())
}

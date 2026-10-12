//! `veilink server` — run the remote relay.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::{info, warn};

use veilink_config::ServerConfig;
use veilink_server::runtime::ServerRuntime;

/// Arguments for `veilink server`.
#[derive(Debug, clap::Args)]
pub struct ServerArgs {
    /// Server configuration file.
    #[arg(long, short = 'c', value_name = "FILE", default_value = "server.yaml")]
    pub config: PathBuf,
    /// Override the listen address.
    #[arg(long, value_name = "ADDR")]
    pub listen: Option<String>,
    /// Override the log level (equivalent to `RUST_LOG`).
    #[arg(long, value_name = "LEVEL")]
    pub log_level: Option<String>,
}

/// Runs the server until interrupted.
pub fn run(args: ServerArgs) -> Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("veilink")
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(run_async(args))
}

async fn run_async(args: ServerArgs) -> Result<ExitCode> {
    let mut config = ServerConfig::load(&args.config)
        .with_context(|| format!("cannot load `{}`", args.config.display()))?;
    if let Some(listen) = &args.listen {
        config.listen = listen.clone();
    }
    if let Some(level) = &args.log_level {
        config.log.level = Some(level.clone());
    }
    let settings = config
        .validate()
        .with_context(|| format!("`{}` is not usable", args.config.display()))?;

    crate::logging::init(crate::logging::InitOptions {
        config: settings.log.clone(),
        default_level: "info",
    })?;
    veilink_transport::install_crypto_provider()
        .map_err(|e| anyhow::anyhow!("no TLS provider: {e}"))?;

    info!("veilink server starting");
    if !settings.allow_private_targets {
        info!("egress policy: loopback, private, link-local and other special-use IPv4 destinations are denied");
    } else {
        warn!("egress policy: private destinations are ALLOWED (testing mode)");
    }

    let runtime = ServerRuntime::bind(&settings)
        .await
        .context("cannot start the server")?;
    let listen = runtime.local_addr()?;
    let ctx = runtime.context();
    info!(listen = %listen, "listening on {listen}");
    info!(
        identity = %ctx.identity.fingerprint_hex(),
        short = %ctx.identity.short_fingerprint(),
        "server identity"
    );
    info!("authentication is mandatory: unauthenticated connections are closed before any request is read");

    let stats_task =
        veilink_server::runtime::spawn_stats_reporter(ctx.clone(), Duration::from_secs(60));

    runtime
        .run(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("the server stopped unexpectedly")?;

    stats_task.abort();
    info!("veilink server stopped");
    Ok(ExitCode::SUCCESS)
}

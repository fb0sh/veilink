//! `veilink client` — run the local encrypted proxy.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::oneshot;
use tracing::{error, info, warn};

use veilink_client::runtime::ClientRuntime;
use veilink_client::uplink::{default_padding, run_uplink, UplinkConfig};
use veilink_config::{ClientConfig, ClientConfigChange, ClientSettings};

/// Arguments for `veilink client`.
#[derive(Debug, clap::Args)]
pub struct ClientArgs {
    /// Client configuration file.
    #[arg(long, short = 'c', value_name = "FILE", default_value = "client.yaml")]
    pub config: PathBuf,
    /// Override the local listen address.
    #[arg(long, value_name = "ADDR")]
    pub listen: Option<String>,
    /// Override the log level (equivalent to `RUST_LOG`).
    #[arg(long, value_name = "LEVEL")]
    pub log_level: Option<String>,
    /// Do not watch the configuration file for changes.
    #[arg(long)]
    pub no_reload: bool,
}

/// Runs the client until interrupted.
pub fn run(args: ClientArgs) -> Result<ExitCode> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("veilink")
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(run_async(args))
}

async fn run_async(args: ClientArgs) -> Result<ExitCode> {
    let mut config = ClientConfig::load(&args.config)
        .with_context(|| format!("cannot load `{}`", args.config.display()))?;
    if let Some(listen) = &args.listen {
        config.listen = Some(listen.clone());
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

    let labels = Labels {
        log_domains: settings.log.log_domains,
    };

    info!("veilink client starting");
    let runtime = ClientRuntime::bind(&settings)
        .await
        .context("cannot bind the local proxy listener")?;
    let ctx = runtime.context();
    let listen = runtime.local_addr()?;
    info!(listen = %listen, "local proxy listening on {listen}");
    info!(transport = %settings.transport, server = %settings.server, "remote server configured");
    info!(rules = settings.rules.len(), "whitelist loaded");
    if settings.rules.is_empty() {
        warn!("the whitelist is empty: every request will be routed DIRECT and no traffic will use the server");
    }
    info!("privacy mode: strict");
    match &settings.expected_identity {
        Some(pin) => info!(
            pin = %pin.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "the server identity is pinned; a different server will be refused"
        ),
        None => info!(
            "the server identity is not pinned; compare the fingerprint printed by the server if you want to detect a swapped deployment"
        ),
    }
    info!("configure your application to use http://{listen} as its HTTP and HTTPS proxy");

    let stats_task =
        veilink_client::runtime::spawn_stats_reporter(ctx.clone(), Duration::from_secs(60));

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server_handle = tokio::spawn({
        let ctx = ctx.clone();
        async move {
            let _ = runtime
                .run(async {
                    let _ = shutdown_rx.await;
                })
                .await;
            let _ = ctx;
        }
    });

    // The uplink supervisor owns the reconnect loop and rebuilds the session when the server
    // endpoint or the key changes.
    let (uplink_stop, uplink_handle) = spawn_uplink(&settings, ctx.clone());

    let mut reload = if args.no_reload {
        None
    } else {
        Some(crate::reload::watch(&args.config)?)
    };

    let mut current = settings;
    let mut uplink_stop = Some(uplink_stop);
    let mut uplink_handle = Some(uplink_handle);

    let mut shutdown = Box::pin(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("interrupt received; shutting down");
                break;
            }
            change = async {
                match reload.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                let Some(event) = change else { continue };
                match crate::reload::reload_client(&args.config, args.listen.as_deref(), args.log_level.as_deref(), &current, &ctx, &labels) {
                    Ok(Some(next)) => {
                        match current.classify_change(&next) {
                            ClientConfigChange::WhitelistOnly => {
                                info!(rules = next.rules.len(), "whitelist reloaded");
                                current = next;
                            }
                            ClientConfigChange::Session => {
                                info!("server endpoint or key changed; rebuilding the secure session");
                                if let Some(stop) = uplink_stop.take() {
                                    let _ = stop.send(());
                                }
                                if let Some(handle) = uplink_handle.take() {
                                    let _ = handle.await;
                                }
                                let (stop, handle) = spawn_uplink(&next, ctx.clone());
                                uplink_stop = Some(stop);
                                uplink_handle = Some(handle);
                                current = next;
                            }
                            ClientConfigChange::Listen => {
                                warn!(
                                    "the listen address changed; a restart is required for it to take effect"
                                );
                                current = next;
                            }
                            ClientConfigChange::None => {}
                        }
                    }
                    Ok(None) => {}
                    Err(error) => {
                        // The previous configuration stays in force.
                        error!(%error, path = %event.path.display(), "configuration reload failed; keeping the previous whitelist");
                    }
                }
            }
        }
    }

    if let Some(stop) = uplink_stop {
        let _ = stop.send(());
    }
    if let Some(handle) = uplink_handle {
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    }
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;
    stats_task.abort();
    info!("veilink client stopped");
    Ok(ExitCode::SUCCESS)
}

/// Log-shaping settings shared with the reload path.
#[derive(Debug, Clone, Copy)]
pub struct Labels {
    /// Whether target domains may be logged.
    pub log_domains: bool,
}

/// Spawns the uplink supervisor, returning its stop handle and join handle.
fn spawn_uplink(
    settings: &ClientSettings,
    ctx: Arc<veilink_client::ClientContext>,
) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let uplink_config = UplinkConfig::from_settings(settings);
    let psk = settings.psk.duplicate();
    let padding = default_padding();
    let (stop_tx, stop_rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        run_uplink(ctx, psk, uplink_config, padding, async move {
            let _ = stop_rx.await;
        })
        .await;
    });
    (stop_tx, handle)
}

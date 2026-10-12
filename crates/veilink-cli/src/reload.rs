//! Configuration hot reload for the client.
//!
//! The watcher is deliberately conservative:
//!
//! * the new configuration is fully parsed and validated **before** anything is replaced;
//! * if it is invalid, the previous whitelist stays in force and the error is logged — a typo in a
//!   rule file must never leave the proxy with no rules, and it must never leave it with rules the
//!   operator did not intend;
//! * a change to the whitelist is applied atomically, so requests that are already in flight keep
//!   the routing decision they started with;
//! * a change to the server endpoint, transport or key triggers a session rebuild instead of being
//!   ignored.
//!
//! The watcher observes the *parent directory* rather than the file, because many editors save by
//! writing a temporary file and renaming it over the target, which does not produce a modify event
//! on the original inode.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use notify::{Event, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{debug, info};

use veilink_client::ClientContext;
use veilink_config::{ClientConfig, ClientSettings};

use crate::commands::client::Labels;

/// A debounced configuration change notification.
#[derive(Debug, Clone)]
pub struct ReloadEvent {
    /// The file that changed.
    pub path: PathBuf,
}

/// Starts watching a configuration file.
pub fn watch(path: &Path) -> Result<mpsc::Receiver<ReloadEvent>> {
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let directory = path
        .parent()
        .map(Path::to_path_buf)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."));

    let (tx, rx) = mpsc::channel(8);
    let watched = path.clone();
    let blocking = std::thread::Builder::new()
        .name("veilink-config-watch".to_string())
        .spawn(move || {
            let (event_tx, event_rx) = std::sync::mpsc::channel::<notify::Result<Event>>();
            let watcher = notify::recommended_watcher(move |result| {
                let _ = event_tx.send(result);
            });
            let mut watcher = match watcher {
                Ok(watcher) => watcher,
                Err(error) => {
                    debug!(%error, "cannot create a filesystem watcher; hot reload is disabled");
                    return;
                }
            };
            if let Err(error) = watcher.watch(&directory, RecursiveMode::NonRecursive) {
                debug!(%error, "cannot watch the configuration directory; hot reload is disabled");
                return;
            }
            let mut last_sent: Option<std::time::Instant> = None;
            for event in event_rx {
                let Ok(event) = event else { continue };
                if !touches(&event, &watched) {
                    continue;
                }
                // Editors often emit several events for one save; collapse them.
                let now = std::time::Instant::now();
                if last_sent
                    .is_some_and(|last| now.duration_since(last) < Duration::from_millis(250))
                {
                    continue;
                }
                last_sent = Some(now);
                if tx
                    .blocking_send(ReloadEvent {
                        path: watched.clone(),
                    })
                    .is_err()
                {
                    return;
                }
            }
        })
        .context("cannot start the configuration watcher thread")?;
    // The watcher thread lives for the process; its handle is intentionally detached.
    std::mem::forget(blocking);
    Ok(rx)
}

fn touches(event: &Event, watched: &Path) -> bool {
    event.paths.iter().any(|candidate| {
        candidate == watched
            || candidate
                .file_name()
                .zip(watched.file_name())
                .map(|(a, b)| a == b)
                .unwrap_or(false)
    })
}

/// Reloads the client configuration.
///
/// Returns the new settings on success. On failure the caller keeps the previous settings and the
/// previous rules remain installed in the context.
pub fn reload_client(
    path: &Path,
    listen_override: Option<&str>,
    log_level_override: Option<&str>,
    current: &ClientSettings,
    ctx: &Arc<ClientContext>,
    labels: &Labels,
) -> Result<Option<ClientSettings>> {
    let mut config =
        ClientConfig::load(path).with_context(|| format!("cannot read `{}`", path.display()))?;
    if let Some(listen) = listen_override {
        config.listen = Some(listen.to_string());
    }
    if let Some(level) = log_level_override {
        config.log.level = Some(level.to_string());
    }
    let next = config
        .validate()
        .with_context(|| format!("`{}` is not valid", path.display()))?;

    // Only the whitelist is swapped here. The router is left alone except when the uplink
    // supervisor decides the session must be rebuilt.
    ctx.set_rules(next.rules.clone());
    info!(
        rules = next.rules.len(),
        log_domains = labels.log_domains,
        changed_from = current.rules.len(),
        "whitelist replaced atomically"
    );
    Ok(Some(next))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_watcher_reports_a_modification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.yaml");
        std::fs::write(&path, "key: x\n").unwrap();

        let mut rx = watch(&path).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        std::fs::write(&path, "key: y\n").unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match rx.try_recv() {
                Ok(event) => {
                    assert!(event.path.ends_with("client.yaml"));
                    return;
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "no reload event was delivered"
                    );
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(other) => panic!("unexpected channel state: {other:?}"),
            }
        }
    }
}

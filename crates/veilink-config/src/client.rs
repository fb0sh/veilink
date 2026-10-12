//! Client configuration (`client.yaml`) and its validated runtime form.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use veilink_crypto::Psk;
use veilink_rules::{Rule, RuleSet};

use crate::common::{
    default_state_dir, parse_listen, Endpoint, LimitsConfig, LogConfig, Transport,
};
use crate::validate::Diagnostics;
use crate::ConfigError;

/// Default local proxy listener.
pub const DEFAULT_CLIENT_LISTEN: &str = "127.0.0.1:7890";

/// Default TLS SNI / certificate subject when the server endpoint is a bare IPv4 literal.
pub const DEFAULT_SERVER_NAME: &str = "veilink.local";

/// Raw client configuration as read from YAML.
///
/// This is deliberately a *raw* model: `key` and `whitelist` are validated in a second phase so
/// that every problem can be reported at once instead of stopping at the first one.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Remote Veilink server endpoint, `HOST:PORT`.
    pub server: String,
    /// Pre-shared authentication key (hex or Base64URL, at least 256 bits).
    pub key: String,
    /// Whitelist rules. Matching requests are forwarded through the server; everything else is
    /// connected directly.
    #[serde(default)]
    pub whitelist: Vec<String>,
    /// Local proxy listen address. Defaults to `127.0.0.1:7890`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    /// Outer transport. Defaults to `h2`.
    #[serde(default)]
    pub transport: Transport,
    /// TLS server name (SNI) presented to the server. Defaults to the `server` host name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// Directory holding generated session caches. Defaults to the platform state directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_dir: Option<PathBuf>,
    /// Logging configuration.
    #[serde(default)]
    pub log: LogConfig,
    /// Resource limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Origin path of this configuration, populated by [`ClientConfig::load`].
    #[serde(skip)]
    source_path: Option<PathBuf>,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `key` is never rendered.
        f.debug_struct("ClientConfig")
            .field("server", &self.server)
            .field("key", &"<redacted>")
            .field("whitelist", &self.whitelist)
            .field("listen", &self.listen)
            .field("transport", &self.transport)
            .field("server_name", &self.server_name)
            .field("state_dir", &self.state_dir)
            .field("log", &self.log)
            .field("limits", &self.limits)
            .finish()
    }
}

/// A validated client configuration, ready to start the client runtime.
pub struct ClientSettings {
    /// Remote server endpoint.
    pub server: Endpoint,
    /// Authentication key.
    pub psk: Psk,
    /// Compiled whitelist.
    pub rules: RuleSet,
    /// Local listener address.
    pub listen: SocketAddr,
    /// Outer transport.
    pub transport: Transport,
    /// TLS SNI value.
    pub server_name: String,
    /// State directory (created lazily by the runtime).
    pub state_dir: PathBuf,
    /// Logging configuration.
    pub log: LogConfig,
    /// Resource limits.
    pub limits: LimitsConfig,
    /// Where the configuration was loaded from, when it came from a file.
    pub source_path: Option<PathBuf>,
}

impl fmt::Debug for ClientSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSettings")
            .field("server", &self.server)
            .field("psk", &"<redacted>")
            .field("rules", &self.rules.len())
            .field("listen", &self.listen)
            .field("transport", &self.transport)
            .field("server_name", &self.server_name)
            .field("state_dir", &self.state_dir)
            .finish()
    }
}

impl ClientConfig {
    /// Parses a client configuration from YAML text.
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        serde_yaml_ng::from_str(text).map_err(|e| ConfigError::Yaml {
            path: PathBuf::from("<memory>"),
            message: e.to_string(),
        })
    }

    /// Reads and parses a client configuration file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut config: ClientConfig =
            serde_yaml_ng::from_str(&text).map_err(|e| ConfigError::Yaml {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;
        config.source_path = Some(path.to_path_buf());
        Ok(config)
    }

    /// Validates the configuration and produces the runtime form.
    pub fn validate(self) -> Result<ClientSettings, ConfigError> {
        let mut diagnostics = Diagnostics::new();

        let server = match Endpoint::parse(&self.server, "server") {
            Ok(e) => Some(e),
            Err(e) => {
                diagnostics.push("server", e.to_string());
                None
            }
        };

        // --- listen ---
        let listen_text = self
            .listen
            .clone()
            .unwrap_or_else(|| DEFAULT_CLIENT_LISTEN.to_string());
        let listen = match parse_listen(&listen_text, "listen") {
            Ok(addr) => Some(addr),
            Err(e) => {
                diagnostics.push("listen", e.to_string());
                None
            }
        };

        // --- key ---
        let psk = match Psk::parse(&self.key) {
            Ok(psk) => Some(psk),
            Err(e) => {
                diagnostics.push("key", e.to_string());
                None
            }
        };

        // --- whitelist: report every faulty rule, not just the first ---
        let mut rules = Vec::with_capacity(self.whitelist.len());
        for (index, raw) in self.whitelist.iter().enumerate() {
            match Rule::parse(raw) {
                Ok(rule) => rules.push(rule),
                Err(e) => diagnostics.push(format!("whitelist[{index}]"), e.to_string()),
            }
        }
        let mut rule_set = None;
        match RuleSet::new(rules) {
            Ok(set) => rule_set = Some(set),
            Err(e) => diagnostics.push("whitelist", e.to_string()),
        }

        // --- server_name ---
        let server_name = match self.server_name.clone() {
            Some(name) => {
                let name = name.trim().to_string();
                if name.is_empty() {
                    diagnostics.push("server_name", "must not be empty");
                    None
                } else if name.parse::<std::net::IpAddr>().is_ok() {
                    // An IP literal is a legal TLS server name but makes an odd SNI value; accept
                    // it for operators who pin the certificate to an address.
                    Some(name)
                } else {
                    match veilink_rules::HostName::parse(&name) {
                        Ok(host) => Some(host.as_str().to_string()),
                        Err(e) => {
                            diagnostics.push("server_name", e.to_string());
                            None
                        }
                    }
                }
            }
            None => server.as_ref().map(|endpoint| {
                if endpoint.host_is_ipv4() {
                    DEFAULT_SERVER_NAME.to_string()
                } else {
                    endpoint.host.clone()
                }
            }),
        };

        diagnostics.into_result()?;

        Ok(ClientSettings {
            server: server.expect("validated above"),
            psk: psk.expect("validated above"),
            rules: rule_set.expect("validated above"),
            listen: listen.expect("validated above"),
            transport: self.transport,
            server_name: server_name.expect("validated above"),
            state_dir: self.state_dir.unwrap_or_else(default_state_dir),
            log: self.log,
            limits: self.limits,
            source_path: self.source_path,
        })
    }
}

/// Fields on `ClientConfig` that must be re-read on hot reload.
///
/// Used by the client runtime to detect whether a reload requires rebuilding the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientConfigChange {
    /// Nothing relevant changed.
    None,
    /// Only the whitelist changed; the existing session can be reused.
    WhitelistOnly,
    /// The server endpoint, key, transport or TLS name changed; the session must be rebuilt.
    Session,
    /// The listen address changed; a restart is required.
    Listen,
}

impl ClientSettings {
    /// Classifies the difference between this configuration and `next`.
    pub fn classify_change(&self, next: &ClientSettings) -> ClientConfigChange {
        if self.listen != next.listen {
            return ClientConfigChange::Listen;
        }
        if self.server != next.server
            || self.transport != next.transport
            || self.server_name != next.server_name
            || !self.psk.ct_eq(&next.psk)
        {
            return ClientConfigChange::Session;
        }
        ClientConfigChange::WhitelistOnly
    }
}

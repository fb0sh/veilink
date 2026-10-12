//! Server configuration (`server.yaml`) and its validated runtime form.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use veilink_crypto::Psk;

use crate::common::{
    default_state_dir, parse_listen, DnsConfig, LimitsConfig, LogConfig, Transport,
};
use crate::validate::Diagnostics;
use crate::ConfigError;

/// Default listen address for the server.
pub const DEFAULT_SERVER_LISTEN: &str = "0.0.0.0:443";

/// Raw server configuration as read from YAML.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Listen address, `HOST:PORT`. Defaults to `0.0.0.0:443`.
    #[serde(default = "default_listen_string")]
    pub listen: String,
    /// Pre-shared authentication key (hex or Base64URL, at least 256 bits).
    pub key: String,
    /// Outer transport. Defaults to `h2`.
    #[serde(default)]
    pub transport: Transport,
    /// Directory holding the generated long-term identity and TLS certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_dir: Option<PathBuf>,
    /// Allow outbound connections to loopback, private, link-local and other special-use IPv4
    /// addresses.
    ///
    /// **Testing only.** It exists so that integration tests can point the server at a target on
    /// `127.0.0.1`; the default (`false`) is the secure production behaviour and denies those
    /// destinations. A warning is logged at startup whenever it is enabled.
    #[serde(default)]
    pub allow_private_targets: bool,
    /// Ports that clients may connect to. Empty means "all ports".
    ///
    /// Restricting egress ports is an additional defence against a compromised client abusing the
    /// server as a general-purpose relay.
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
    /// DNS resolver configuration.
    #[serde(default)]
    pub dns: DnsConfig,
    /// Resource limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Logging configuration.
    #[serde(default)]
    pub log: LogConfig,
    /// Origin path of this configuration, populated by [`ServerConfig::load`].
    #[serde(skip)]
    source_path: Option<PathBuf>,
}

fn default_listen_string() -> String {
    DEFAULT_SERVER_LISTEN.to_string()
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("listen", &self.listen)
            .field("key", &"<redacted>")
            .field("transport", &self.transport)
            .field("state_dir", &self.state_dir)
            .field("allow_private_targets", &self.allow_private_targets)
            .field("allowed_ports", &self.allowed_ports)
            .field("dns", &self.dns)
            .field("limits", &self.limits)
            .finish()
    }
}

/// A validated server configuration, ready to start the server runtime.
///
/// `Clone` is derived so that a caller can build a variant (for example, to probe a different
/// listen port) without re-reading and re-validating the file.
#[derive(Clone)]
pub struct ServerSettings {
    /// Listen address.
    pub listen: SocketAddr,
    /// Authentication key.
    pub psk: Psk,
    /// Outer transport.
    pub transport: Transport,
    /// State directory for the long-term identity.
    pub state_dir: PathBuf,
    /// Whether special-use destinations are permitted.
    pub allow_private_targets: bool,
    /// Permitted egress ports (empty = all).
    pub allowed_ports: Vec<u16>,
    /// DNS configuration.
    pub dns: DnsConfig,
    /// Resource limits.
    pub limits: LimitsConfig,
    /// Logging configuration.
    pub log: LogConfig,
    /// Where the configuration was loaded from, when it came from a file.
    pub source_path: Option<PathBuf>,
}

impl fmt::Debug for ServerSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerSettings")
            .field("listen", &self.listen)
            .field("psk", &"<redacted>")
            .field("transport", &self.transport)
            .field("state_dir", &self.state_dir)
            .field("allow_private_targets", &self.allow_private_targets)
            .field("allowed_ports", &self.allowed_ports)
            .finish()
    }
}

impl ServerConfig {
    /// Parses a server configuration from YAML text.
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        serde_yaml_ng::from_str(text).map_err(|e| ConfigError::Yaml {
            path: PathBuf::from("<memory>"),
            message: e.to_string(),
        })
    }

    /// Reads and parses a server configuration file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut config: ServerConfig =
            serde_yaml_ng::from_str(&text).map_err(|e| ConfigError::Yaml {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;
        config.source_path = Some(path.to_path_buf());
        Ok(config)
    }

    /// Validates the configuration and produces the runtime form.
    pub fn validate(self) -> Result<ServerSettings, ConfigError> {
        let mut diagnostics = Diagnostics::new();

        let listen = match parse_listen(&self.listen, "listen") {
            Ok(addr) => Some(addr),
            Err(e) => {
                diagnostics.push("listen", e.to_string());
                None
            }
        };

        let psk = match Psk::parse(&self.key) {
            Ok(psk) => Some(psk),
            Err(e) => {
                diagnostics.push("key", e.to_string());
                None
            }
        };

        // Egress port allow-list: reject duplicates and port 0.
        let mut allowed_ports = Vec::with_capacity(self.allowed_ports.len());
        for (index, port) in self.allowed_ports.iter().enumerate() {
            if *port == 0 {
                diagnostics.push(
                    format!("allowed_ports[{index}]"),
                    "port 0 is not a valid destination port",
                );
                continue;
            }
            if allowed_ports.contains(port) {
                diagnostics.push(
                    format!("allowed_ports[{index}]"),
                    format!("duplicate port {port}"),
                );
                continue;
            }
            allowed_ports.push(*port);
        }

        // DNS server entries must be `IP:PORT` or `IP`.
        for (index, entry) in self.dns.servers.iter().enumerate() {
            if let Err(message) = validate_dns_server(entry) {
                diagnostics.push(format!("dns.servers[{index}]"), message);
            }
        }
        if self.dns.timeout_ms == 0 {
            diagnostics.push("dns.timeout_ms", "must be greater than zero");
        }
        if self.dns.attempts == 0 {
            diagnostics.push("dns.attempts", "must be at least 1");
        }
        if self.dns.cache_size == 0 {
            diagnostics.push("dns.cache_size", "must be greater than zero");
        }

        if self.limits.max_connections == 0 {
            diagnostics.push("limits.max_connections", "must be greater than zero");
        }
        if self.limits.max_streams_per_session == 0 {
            diagnostics.push(
                "limits.max_streams_per_session",
                "must be greater than zero",
            );
        }
        if self.limits.connect_timeout_ms == 0 {
            diagnostics.push("limits.connect_timeout_ms", "must be greater than zero");
        }

        if let Some(addr) = listen {
            if addr.port() == 0 {
                diagnostics.push("listen", "port 0 is not a valid listen port");
            }
        }

        diagnostics.into_result()?;

        Ok(ServerSettings {
            listen: listen.expect("validated above"),
            psk: psk.expect("validated above"),
            transport: self.transport,
            state_dir: self.state_dir.unwrap_or_else(default_state_dir),
            allow_private_targets: self.allow_private_targets,
            allowed_ports,
            dns: self.dns,
            limits: self.limits,
            log: self.log,
            source_path: self.source_path,
        })
    }
}

fn validate_dns_server(entry: &str) -> Result<(), String> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Err("must not be empty".to_string());
    }
    let (ip_text, port_text) = match trimmed.rsplit_once(':') {
        Some((ip, port)) if !ip.contains(':') => (ip, Some(port)),
        _ => (trimmed, None),
    };
    let ip: IpAddr = ip_text
        .parse()
        .map_err(|_| format!("`{trimmed}` does not start with a valid IP address"))?;
    if let Some(port) = port_text {
        let port: u16 = port
            .parse()
            .map_err(|_| format!("`{trimmed}` has an invalid port"))?;
        if port == 0 {
            return Err(format!("`{trimmed}` uses port 0"));
        }
    }
    if ip.is_unspecified() {
        return Err(format!("`{trimmed}` uses an unspecified address"));
    }
    Ok(())
}

/// Returns the addresses that should appear as subject alternative names on the generated
/// self-signed certificate for a given listen address.
pub fn certificate_alt_names(listen: SocketAddr) -> Vec<String> {
    let mut names = vec![crate::client::DEFAULT_SERVER_NAME.to_string()];
    match listen.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => names.push(v4.to_string()),
        IpAddr::V6(v6) if !v6.is_unspecified() => names.push(v6.to_string()),
        _ => {}
    }
    // A stable placeholder so that a certificate generated for a wildcard bind still chains to a
    // resolvable name rather than to nothing at all.
    if names.len() == 1 {
        names.push(Ipv4Addr::LOCALHOST.to_string());
    }
    names
}

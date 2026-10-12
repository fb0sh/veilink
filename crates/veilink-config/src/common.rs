//! Shared configuration building blocks: transport selection, logging, limits and paths.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The outer transport used between the client and the server.
///
/// Both variants run the same `VLP/1` framing and the same per-frame cryptography; the difference
/// is only how the encrypted byte stream is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// TLS 1.3 over TCP with a length-prefixed `VLP/1` frame stream. Always available and the
    /// lowest-overhead option.
    Tls,
    /// TLS 1.3 with an HTTP/2 session whose request/response body pair carries the `VLP/1` frame
    /// stream. Selected by default because the outer traffic then resembles ordinary HTTP/2.
    #[default]
    H2,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Transport::Tls => "tls",
            Transport::H2 => "h2",
        })
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// Human-readable single-line records.
    #[default]
    Text,
    /// Newline-delimited JSON records.
    Json,
}

/// Logging configuration.
///
/// Privacy-preserving defaults: target domains and URLs are not logged unless
/// [`LogConfig::log_domains`] is explicitly enabled, and headers/body contents are never logged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Log level filter; equivalent to `RUST_LOG`. Defaults to `info`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    /// Output format. Defaults to plain text.
    #[serde(default)]
    pub format: LogFormat,
    /// When `true`, target domain names are written to the log. Defaults to `false`, in which case
    /// targets are printed as `<redacted>`.
    #[serde(default)]
    pub log_domains: bool,
}

/// DNS resolution settings used by the server's remote resolver.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// Upstream name servers as `IP:PORT`. Empty means "use the system resolver".
    #[serde(default)]
    pub servers: Vec<String>,
    /// Maximum number of cached lookups.
    #[serde(default = "DnsConfig::default_cache_size")]
    pub cache_size: usize,
    /// Per-query timeout in milliseconds.
    #[serde(default = "DnsConfig::default_timeout_ms")]
    pub timeout_ms: u64,
    /// Number of attempts per query before giving up.
    #[serde(default = "DnsConfig::default_attempts")]
    pub attempts: usize,
}

impl DnsConfig {
    fn default_cache_size() -> usize {
        512
    }

    fn default_timeout_ms() -> u64 {
        5_000
    }

    fn default_attempts() -> usize {
        2
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            servers: Vec::new(),
            cache_size: Self::default_cache_size(),
            timeout_ms: Self::default_timeout_ms(),
            attempts: Self::default_attempts(),
        }
    }
}

/// Resource limits. Every value has a conservative production default.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Maximum number of simultaneously accepted outer connections.
    #[serde(default = "LimitsConfig::default_max_connections")]
    pub max_connections: usize,
    /// Maximum number of concurrently open streams inside one session.
    #[serde(default = "LimitsConfig::default_max_streams")]
    pub max_streams_per_session: usize,
    /// TCP connect timeout for outbound connections, in milliseconds.
    #[serde(default = "LimitsConfig::default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// Idle timeout for an outbound stream, in milliseconds.
    #[serde(default = "LimitsConfig::default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    /// Maximum size of a single reassembled HTTP request head, in bytes.
    #[serde(default = "LimitsConfig::default_max_header_bytes")]
    pub max_header_bytes: usize,
    /// Maximum number of new outer connections accepted per second, per remote address.
    #[serde(default = "LimitsConfig::default_accept_rate")]
    pub accept_rate_per_second: u32,
}

impl LimitsConfig {
    fn default_max_connections() -> usize {
        1024
    }
    fn default_max_streams() -> usize {
        512
    }
    fn default_connect_timeout_ms() -> u64 {
        10_000
    }
    fn default_idle_timeout_ms() -> u64 {
        300_000
    }
    fn default_max_header_bytes() -> usize {
        64 * 1024
    }
    fn default_accept_rate() -> u32 {
        64
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            max_connections: Self::default_max_connections(),
            max_streams_per_session: Self::default_max_streams(),
            connect_timeout_ms: Self::default_connect_timeout_ms(),
            idle_timeout_ms: Self::default_idle_timeout_ms(),
            max_header_bytes: Self::default_max_header_bytes(),
            accept_rate_per_second: Self::default_accept_rate(),
        }
    }
}

/// A `host:port` endpoint as written in the configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Host part: an IPv4 literal or a DNS name.
    pub host: String,
    /// Port number; never zero.
    pub port: u16,
}

impl Endpoint {
    /// Parses and validates `host:port`.
    pub fn parse(input: &str, field: &str) -> Result<Self, super::ConfigError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(super::ConfigError::field(field, "must not be empty"));
        }
        if trimmed.starts_with('[') || trimmed.contains("::") {
            return Err(super::ConfigError::field(
                field,
                format!("`{trimmed}` is an IPv6 endpoint; this release only supports IPv4"),
            ));
        }
        let (host, port_text) = trimmed.rsplit_once(':').ok_or_else(|| {
            super::ConfigError::field(field, format!("`{trimmed}` must be written as `HOST:PORT`"))
        })?;
        if host.is_empty() {
            return Err(super::ConfigError::field(
                field,
                format!("`{trimmed}` is missing a host"),
            ));
        }
        if host.contains(':') {
            return Err(super::ConfigError::field(
                field,
                format!("`{trimmed}` contains more than one `:`"),
            ));
        }
        let port: u16 = port_text.parse().map_err(|_| {
            super::ConfigError::field(
                field,
                format!("`{port_text}` is not a valid port number (expected 1-65535)"),
            )
        })?;
        if port == 0 {
            return Err(super::ConfigError::field(
                field,
                "port 0 is not a valid destination port",
            ));
        }
        Ok(Endpoint {
            host: host.to_string(),
            port,
        })
    }

    /// True when the host is an IPv4 literal.
    pub fn host_is_ipv4(&self) -> bool {
        self.host.parse::<std::net::Ipv4Addr>().is_ok()
    }

    /// Renders `host:port`.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Parses into a [`SocketAddr`] when the host is already an IPv4 literal.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.host
            .parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, self.port))
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Parses a `HOST:PORT` listen address into a [`SocketAddr`].
pub fn parse_listen(input: &str, field: &str) -> Result<SocketAddr, super::ConfigError> {
    let trimmed = input.trim();
    trimmed.parse::<SocketAddr>().map_err(|_| {
        super::ConfigError::field(
            field,
            format!("`{trimmed}` is not a valid listen address such as `127.0.0.1:7890`"),
        )
    })
}

/// Returns the default state directory used for long-term identity material.
///
/// * `$VEILINK_STATE_DIR` when set;
/// * `$XDG_STATE_HOME/veilink` on Linux when set;
/// * `~/.local/state/veilink` on Linux;
/// * `%APPDATA%\veilink` on Windows;
/// * `~/Library/Application Support/veilink` on macOS;
/// * `./state` as a last resort.
pub fn default_state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("VEILINK_STATE_DIR") {
        return PathBuf::from(dir);
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return Path::new(&appdata).join("veilink");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home)
                .join("Library")
                .join("Application Support")
                .join("veilink");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
            return Path::new(&xdg).join("veilink");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home)
                .join(".local")
                .join("state")
                .join("veilink");
        }
    }
    PathBuf::from("state")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parsing() {
        let e = Endpoint::parse("203.0.113.10:443", "server").unwrap();
        assert_eq!(e.host, "203.0.113.10");
        assert_eq!(e.port, 443);
        assert!(e.host_is_ipv4());
        assert!(e.socket_addr().is_some());

        let d = Endpoint::parse("vps.example.com:8443", "server").unwrap();
        assert!(!d.host_is_ipv4());
        assert!(d.socket_addr().is_none());
    }

    #[test]
    fn endpoint_rejects_bad_input() {
        assert!(Endpoint::parse("", "server").is_err());
        assert!(Endpoint::parse("no-port", "server").is_err());
        assert!(Endpoint::parse("host:0", "server").is_err());
        assert!(Endpoint::parse("host:99999", "server").is_err());
        assert!(Endpoint::parse("host:abc", "server").is_err());
        assert!(Endpoint::parse("[::1]:443", "server").is_err());
        assert!(Endpoint::parse("2001:db8::1:443", "server").is_err());
    }

    #[test]
    fn listen_parsing() {
        assert_eq!(
            parse_listen("127.0.0.1:7890", "listen").unwrap().port(),
            7890
        );
        assert!(parse_listen("127.0.0.1", "listen").is_err());
        assert!(parse_listen("localhost:7890", "listen").is_err());
    }

    #[test]
    fn default_state_dir_is_absolute_or_fallback() {
        let dir = default_state_dir();
        assert!(!dir.as_os_str().is_empty());
    }

    #[test]
    fn limits_defaults_are_sane() {
        let l = LimitsConfig::default();
        assert!(l.max_connections > 0);
        assert!(l.max_streams_per_session > 0);
        assert!(l.connect_timeout_ms > 0);
        assert!(l.max_header_bytes >= 8192);
    }
}

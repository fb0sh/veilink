//! # veilink-config
//!
//! Loading and validation of the two Veilink configuration files.
//!
//! The operator-facing surface is intentionally tiny. A client configuration needs exactly three
//! things — the server endpoint, the authentication key and the whitelist:
//!
//! ```yaml
//! server: "203.0.113.10:443"
//! key: "YOUR_SECRET_KEY"
//!
//! whitelist:
//!   - "DOMAIN,github.com"
//!   - "DOMAIN-SUFFIX,githubusercontent.com"
//!   - "IP,1.1.1.1"
//!   - "CIDR,140.82.112.0/24"
//! ```
//!
//! Everything else (padding, scheduling, cover traffic, key rotation, multiplexing) is part of the
//! protocol and is always on. The few remaining knobs — listen address, transport, log level,
//! resource limits — all have secure defaults.
//!
//! ## Two-phase validation
//!
//! [`ClientConfig::load`] only performs YAML decoding, including rejection of unknown fields
//! (`deny_unknown_fields`). [`ClientConfig::validate`] then checks every value and reports *all*
//! problems at once through [`Diagnostics`], which is what `veilink check` prints.
//!
//! ```
//! # use veilink_config::ClientConfig;
//! let yaml = r#"
//! server: "203.0.113.10:443"
//! key: "9f8c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5"
//! whitelist:
//!   - "DOMAIN-SUFFIX,github.com"
//! "#;
//! let settings = ClientConfig::from_yaml(yaml).unwrap().validate().unwrap();
//! assert_eq!(settings.server.port, 443);
//! assert_eq!(settings.rules.len(), 1);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod common;
pub mod server;
pub mod validate;

pub use client::{
    ClientConfig, ClientConfigChange, ClientSettings, DEFAULT_CLIENT_LISTEN, DEFAULT_SERVER_NAME,
};
pub use common::{
    default_state_dir, parse_listen, DnsConfig, Endpoint, LimitsConfig, LogConfig, LogFormat,
    Transport,
};
pub use server::{certificate_alt_names, ServerConfig, ServerSettings, DEFAULT_SERVER_LISTEN};
pub use validate::{Diagnostic, Diagnostics};

use std::path::PathBuf;

/// Errors raised while loading or validating a configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("failed to read `{}`: {source}", path.display())]
    Io {
        /// Path that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The file was not valid YAML, or contained unknown fields.
    #[error("`{}` is not a valid Veilink configuration: {message}", path.display())]
    Yaml {
        /// Path that failed to parse.
        path: PathBuf,
        /// Underlying YAML error, including line and column.
        message: String,
    },
    /// One or more values failed validation.
    #[error("{0}")]
    Invalid(#[from] Diagnostics),
}

impl ConfigError {
    /// Builds a single-field validation error.
    pub(crate) fn field(field: &str, message: impl Into<String>) -> Self {
        let mut diagnostics = Diagnostics::new();
        diagnostics.push(field, message);
        ConfigError::Invalid(diagnostics)
    }

    /// True when the failure was caused by the file's content rather than by the environment.
    pub fn is_content_error(&self) -> bool {
        matches!(self, ConfigError::Yaml { .. } | ConfigError::Invalid(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_KEY: &str = "9f8c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5";

    fn client_yaml(extra: &str) -> String {
        format!("server: \"203.0.113.10:443\"\nkey: \"{GOOD_KEY}\"\n{extra}")
    }

    #[test]
    fn minimal_client_config_validates() {
        let settings = ClientConfig::from_yaml(&client_yaml(""))
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(settings.server.authority(), "203.0.113.10:443");
        assert_eq!(settings.listen.to_string(), DEFAULT_CLIENT_LISTEN);
        assert_eq!(settings.server_name, DEFAULT_SERVER_NAME);
        assert_eq!(settings.transport, Transport::H2);
        assert!(settings.rules.is_empty());
    }

    #[test]
    fn whitelist_is_compiled() {
        let yaml = client_yaml(
            "whitelist:\n  - \"DOMAIN,github.com\"\n  - \"DOMAIN-SUFFIX,githubusercontent.com\"\n  - \"IP,1.1.1.1\"\n  - \"CIDR,140.82.112.0/24\"\n",
        );
        let settings = ClientConfig::from_yaml(&yaml).unwrap().validate().unwrap();
        assert_eq!(settings.rules.len(), 4);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let yaml = client_yaml("surprise: true\n");
        let err = ClientConfig::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains("surprise"), "{err}");
    }

    #[test]
    fn missing_required_fields_are_rejected() {
        assert!(ClientConfig::from_yaml("key: \"x\"").is_err());
        assert!(ClientConfig::from_yaml("server: \"a:1\"").is_err());
    }

    #[test]
    fn all_whitelist_errors_are_reported_together() {
        let yaml = client_yaml(
            "whitelist:\n  - \"BOGUS,a\"\n  - \"DOMAIN,a..b\"\n  - \"CIDR,999.1.1.1/24\"\n  - \"IP,::1\"\n",
        );
        let err = ClientConfig::from_yaml(&yaml)
            .unwrap()
            .validate()
            .unwrap_err();
        match err {
            ConfigError::Invalid(d) => {
                assert_eq!(d.len(), 4, "expected four diagnostics, got {d}");
                let fields: Vec<&str> = d.items().iter().map(|i| i.field.as_str()).collect();
                assert_eq!(
                    fields,
                    vec![
                        "whitelist[0]",
                        "whitelist[1]",
                        "whitelist[2]",
                        "whitelist[3]"
                    ]
                );
            }
            other => panic!("expected validation diagnostics, got {other}"),
        }
    }

    #[test]
    fn duplicate_rules_are_reported() {
        let yaml = client_yaml("whitelist:\n  - \"DOMAIN,a.com\"\n  - \"domain,A.com.\"\n");
        let err = ClientConfig::from_yaml(&yaml)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("duplicate"), "{err}");
    }

    #[test]
    fn bad_key_reports_key_field() {
        let yaml = "server: \"203.0.113.10:443\"\nkey: \"hunter2\"\n";
        let err = ClientConfig::from_yaml(yaml)
            .unwrap()
            .validate()
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("key"), "{text}");
        assert!(text.contains("hexadecimal"), "{text}");
        assert!(text.contains("keygen"), "{text}");
    }

    #[test]
    fn listen_override_and_bad_listen() {
        let ok = ClientConfig::from_yaml(&client_yaml("listen: \"127.0.0.1:1080\"\n"))
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(ok.listen.port(), 1080);

        let err = ClientConfig::from_yaml(&client_yaml("listen: \"nonsense\"\n"))
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("listen"), "{err}");
    }

    #[test]
    fn ipv6_server_endpoint_is_rejected() {
        let yaml = format!("server: \"[2001:db8::1]:443\"\nkey: \"{GOOD_KEY}\"\n");
        let err = ClientConfig::from_yaml(&yaml)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("IPv6"), "{err}");
    }

    #[test]
    fn server_config_defaults() {
        let yaml = format!("key: \"{GOOD_KEY}\"\n");
        let settings = ServerConfig::from_yaml(&yaml).unwrap().validate().unwrap();
        assert_eq!(settings.listen.to_string(), DEFAULT_SERVER_LISTEN);
        assert!(!settings.allow_private_targets);
        assert!(settings.allowed_ports.is_empty());
        assert_eq!(settings.dns.timeout_ms, 5_000);
    }

    #[test]
    fn server_config_rejects_bad_dns_and_ports() {
        let yaml = format!(
            "key: \"{GOOD_KEY}\"\ndns:\n  servers: [\"not-an-ip\", \"1.1.1.1:0\"]\nallowed_ports: [0, 443, 443]\n"
        );
        let err = ServerConfig::from_yaml(&yaml)
            .unwrap()
            .validate()
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("dns.servers[0]"), "{text}");
        assert!(text.contains("dns.servers[1]"), "{text}");
        assert!(text.contains("allowed_ports[0]"), "{text}");
        assert!(text.contains("allowed_ports[2]"), "{text}");
    }

    #[test]
    fn server_config_rejects_unknown_fields() {
        let yaml = format!("key: \"{GOOD_KEY}\"\nmystery: 1\n");
        assert!(ServerConfig::from_yaml(&yaml).is_err());
    }

    #[test]
    fn change_classification() {
        let base = ClientConfig::from_yaml(&client_yaml("whitelist: [\"DOMAIN,a.com\"]\n"))
            .unwrap()
            .validate()
            .unwrap();

        let same = ClientConfig::from_yaml(&client_yaml("whitelist: [\"DOMAIN,a.com\"]\n"))
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(
            base.classify_change(&same),
            ClientConfigChange::WhitelistOnly
        );

        let changed_rules =
            ClientConfig::from_yaml(&client_yaml("whitelist: [\"DOMAIN,b.com\"]\n"))
                .unwrap()
                .validate()
                .unwrap();
        assert_eq!(
            base.classify_change(&changed_rules),
            ClientConfigChange::WhitelistOnly
        );

        let changed_server = ClientConfig::from_yaml(&format!(
            "server: \"203.0.113.11:443\"\nkey: \"{GOOD_KEY}\"\n"
        ))
        .unwrap()
        .validate()
        .unwrap();
        assert_eq!(
            base.classify_change(&changed_server),
            ClientConfigChange::Session
        );

        let changed_key = ClientConfig::from_yaml(
            "server: \"203.0.113.10:443\"\nkey: \"f0e1d2c3b4a5968778695a4b3c2d1e0f112233445566778899aabbccddeeff00\"\n",
        )
        .unwrap()
        .validate()
        .unwrap();
        assert_eq!(
            base.classify_change(&changed_key),
            ClientConfigChange::Session
        );

        let changed_listen = ClientConfig::from_yaml(&client_yaml("listen: \"127.0.0.1:9999\"\n"))
            .unwrap()
            .validate()
            .unwrap();
        assert_eq!(
            base.classify_change(&changed_listen),
            ClientConfigChange::Listen
        );
    }

    #[test]
    fn secrets_never_appear_in_debug_output() {
        let config = ClientConfig::from_yaml(&client_yaml("")).unwrap();
        let text = format!("{config:?}");
        assert!(!text.contains(GOOD_KEY), "{text}");
        assert!(text.contains("redacted"));

        let settings = config.validate().unwrap();
        let text = format!("{settings:?}");
        assert!(!text.contains(GOOD_KEY), "{text}");
        assert!(text.contains("redacted"));
    }

    #[test]
    fn certificate_alt_names_include_configured_ip() {
        let names = certificate_alt_names("0.0.0.0:443".parse().unwrap());
        assert!(names.iter().any(|n| n == DEFAULT_SERVER_NAME));
        assert!(names.iter().any(|n| n == "127.0.0.1"));
        let names = certificate_alt_names("203.0.113.10:443".parse().unwrap());
        assert!(names.iter().any(|n| n == "203.0.113.10"));
    }
}

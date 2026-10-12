//! `veilink check` — validate a configuration file without starting anything.

use std::path::PathBuf;

use anyhow::Result;
use veilink_config::{ClientConfig, ClientSettings, ConfigError, ServerConfig, ServerSettings};

/// Which configuration schema to validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ConfigType {
    /// Decide from the file contents (a `server:` or `whitelist:` key means a client file).
    Auto,
    /// Validate as `client.yaml`.
    Client,
    /// Validate as `server.yaml`.
    Server,
}

/// Arguments for `veilink check`.
#[derive(Debug, clap::Args)]
pub struct CheckArgs {
    /// Configuration file to validate.
    #[arg(long, short = 'c', value_name = "FILE")]
    pub config: PathBuf,
    /// Force a configuration schema instead of detecting it.
    #[arg(long, value_enum, default_value_t = ConfigType::Auto)]
    pub r#type: ConfigType,
    /// Print the effective settings after validation. Secrets are never printed.
    #[arg(long)]
    pub verbose: bool,
}

/// Runs `veilink check`. Returns `Ok(true)` when the configuration is valid.
pub fn run(args: &CheckArgs) -> Result<bool> {
    let path = &args.config;
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("error: cannot read `{}`: {e}", path.display());
            return Ok(false);
        }
    };

    let kind = match args.r#type {
        ConfigType::Auto => detect(&text),
        explicit => explicit,
    };

    let outcome: Result<(), String> = match kind {
        ConfigType::Server => ServerConfig::from_yaml(&text)
            .map_err(render)
            .and_then(|config| config.validate().map_err(render))
            .map(|settings: ServerSettings| {
                if args.verbose {
                    print!("{}", render_server(&settings));
                }
            }),
        _ => ClientConfig::from_yaml(&text)
            .map_err(render)
            .and_then(|config| config.validate().map_err(render))
            .map(|settings: ClientSettings| {
                if args.verbose {
                    print!("{}", render_client(&settings));
                }
            }),
    };

    match outcome {
        Ok(()) => {
            println!(
                "OK: `{}` is a valid Veilink {} configuration.",
                path.display(),
                match kind {
                    ConfigType::Server => "server",
                    _ => "client",
                }
            );
            Ok(true)
        }
        Err(message) => {
            eprintln!("error: `{}` is not valid:", path.display());
            for line in message.lines() {
                eprintln!("  {line}");
            }
            Ok(false)
        }
    }
}

fn render(error: ConfigError) -> String {
    error.to_string()
}

/// Builds the human-readable report for a client configuration.
///
/// The report is a `String` rather than a series of `println!` calls so that it can be asserted on:
/// whether the identity pin is in force is a security-relevant fact, and a test should be able to
/// check that `check` reports it rather than a human having to eyeball the output.
fn render_client(settings: &ClientSettings) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "  server        : {}", settings.server);
    let _ = writeln!(out, "  server_name   : {}", settings.server_name);
    let _ = writeln!(out, "  listen        : {}", settings.listen);
    let _ = writeln!(out, "  transport     : {}", settings.transport);
    let _ = writeln!(out, "  state_dir     : {}", settings.state_dir.display());
    // Printed deliberately: whether the server identity is pinned is a security-relevant setting,
    // and `check` is the tool an operator uses to confirm that the file says what they intended.
    match &settings.expected_identity {
        Some(pin) => {
            let rendered = pin
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            let _ = writeln!(out, "  identity pin  : {rendered}");
        }
        None => {
            let _ = writeln!(out, "  identity pin  : (not set: only the PSK is trusted)");
        }
    }
    let _ = writeln!(out, "  whitelist     : {} rule(s)", settings.rules.len());
    for (index, rule) in settings.rules.rules().iter().enumerate() {
        let _ = writeln!(out, "    [{index}] {}", rule.identity());
    }
    if settings.rules.is_empty() {
        let _ = writeln!(out, "    (empty: every request will be routed DIRECT)");
    }
    out
}

/// Builds the human-readable report for a server configuration.
fn render_server(settings: &ServerSettings) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "  listen        : {}", settings.listen);
    let _ = writeln!(out, "  transport     : {}", settings.transport);
    let _ = writeln!(out, "  state_dir     : {}", settings.state_dir.display());
    let _ = writeln!(
        out,
        "  egress policy : {}",
        if settings.allow_private_targets {
            "ALLOW PRIVATE (testing only)"
        } else {
            "deny loopback/private/special-use"
        }
    );
    if settings.allowed_ports.is_empty() {
        let _ = writeln!(out, "  allowed_ports : all");
    } else {
        let _ = writeln!(out, "  allowed_ports : {:?}", settings.allowed_ports);
    }
    let _ = writeln!(
        out,
        "  dns           : {}",
        if settings.dns.servers.is_empty() {
            "system resolver".to_string()
        } else {
            settings.dns.servers.join(", ")
        }
    );
    let _ = writeln!(out, "  max_conns     : {}", settings.limits.max_connections);
    let _ = writeln!(
        out,
        "  max_streams   : {} per session",
        settings.limits.max_streams_per_session
    );
    out
}

/// Chooses a schema from the file contents.
///
/// The two schemas are unambiguous: `client.yaml` requires `server`, and `server.yaml` rejects it
/// as an unknown field. A `whitelist` key also only exists on the client side.
fn detect(text: &str) -> ConfigType {
    let looks_like_client = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .any(|line| line.starts_with("server:") || line.starts_with("whitelist:"));
    if looks_like_client {
        ConfigType::Client
    } else {
        ConfigType::Server
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pinned_identity_is_reported() {
        let key = "5ANdWZP0a5jcEIUz3Yb1z2DBqt1Q4C8pJ6CxB1n4n2A";
        let pinned = format!(
            "server: \"203.0.113.10:443\"\nkey: \"{key}\"\nserver_identity_pin: \"aabbccdd\"\n\
             whitelist:\n  - \"DOMAIN,example.test\"\n"
        );
        let settings = ClientConfig::from_yaml(&pinned)
            .unwrap()
            .validate()
            .unwrap();
        let report = render_client(&settings);
        assert!(
            report.contains("identity pin  : aa:bb:cc:dd"),
            "the pin was not reported:\n{report}"
        );
        assert!(report.contains("DOMAIN,example.test"), "{report}");
        assert!(!report.contains("not set"), "{report}");

        // Without a pin the report must say so, rather than staying silent about a security
        // relevant default.
        let unpinned = format!(
            "server: \"203.0.113.10:443\"\nkey: \"{key}\"\nwhitelist:\n  - \"DOMAIN,example.test\"\n"
        );
        let settings = ClientConfig::from_yaml(&unpinned)
            .unwrap()
            .validate()
            .unwrap();
        let report = render_client(&settings);
        assert!(
            report.contains("not set: only the PSK is trusted"),
            "an absent pin was not reported:\n{report}"
        );
    }

    #[test]
    fn an_empty_whitelist_is_called_out() {
        let key = "5ANdWZP0a5jcEIUz3Yb1z2DBqt1Q4C8pJ6CxB1n4n2A";
        let yaml = format!("server: \"203.0.113.10:443\"\nkey: \"{key}\"\n");
        let settings = ClientConfig::from_yaml(&yaml).unwrap().validate().unwrap();
        let report = render_client(&settings);
        assert!(
            report.contains("every request will be routed DIRECT"),
            "an empty whitelist was not called out:\n{report}"
        );
    }

    #[test]
    fn the_server_report_names_the_egress_policy() {
        let key = "5ANdWZP0a5jcEIUz3Yb1z2DBqt1Q4C8pJ6CxB1n4n2A";
        let strict = format!("listen: \"127.0.0.1:8443\"\nkey: \"{key}\"\n");
        let settings = ServerConfig::from_yaml(&strict)
            .unwrap()
            .validate()
            .unwrap();
        let report = render_server(&settings);
        assert!(
            report.contains("deny loopback/private/special-use"),
            "{report}"
        );
        assert!(report.contains("allowed_ports : all"), "{report}");

        // The permissive mode is dangerous and must be impossible to miss in the report.
        let permissive = format!(
            "listen: \"127.0.0.1:8443\"\nkey: \"{key}\"\nallow_private_targets: true\n\
             allowed_ports: [80, 443]\n"
        );
        let settings = ServerConfig::from_yaml(&permissive)
            .unwrap()
            .validate()
            .unwrap();
        let report = render_server(&settings);
        assert!(report.contains("ALLOW PRIVATE"), "{report}");
        assert!(report.contains("allowed_ports : [80, 443]"), "{report}");
    }

    #[test]
    fn auto_detection() {
        assert_eq!(
            detect("server: \"1.2.3.4:443\"\nkey: \"x\"\n"),
            ConfigType::Client
        );
        assert_eq!(
            detect("whitelist:\n  - \"DOMAIN,a.com\"\n"),
            ConfigType::Client
        );
        assert_eq!(
            detect("listen: \"0.0.0.0:443\"\nkey: \"x\"\n"),
            ConfigType::Server
        );
        assert_eq!(detect("# comment only\n"), ConfigType::Server);
    }
}

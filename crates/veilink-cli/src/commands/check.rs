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
                    print_server(&settings);
                }
            }),
        _ => ClientConfig::from_yaml(&text)
            .map_err(render)
            .and_then(|config| config.validate().map_err(render))
            .map(|settings: ClientSettings| {
                if args.verbose {
                    print_client(&settings);
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

fn print_client(settings: &ClientSettings) {
    println!("  server        : {}", settings.server);
    println!("  server_name   : {}", settings.server_name);
    println!("  listen        : {}", settings.listen);
    println!("  transport     : {}", settings.transport);
    println!("  state_dir     : {}", settings.state_dir.display());
    println!("  whitelist     : {} rule(s)", settings.rules.len());
    for (index, rule) in settings.rules.rules().iter().enumerate() {
        println!("    [{index}] {}", rule.identity());
    }
    if settings.rules.is_empty() {
        println!("    (empty: every request will be routed DIRECT)");
    }
}

fn print_server(settings: &ServerSettings) {
    println!("  listen        : {}", settings.listen);
    println!("  transport     : {}", settings.transport);
    println!("  state_dir     : {}", settings.state_dir.display());
    println!(
        "  egress policy : {}",
        if settings.allow_private_targets {
            "ALLOW PRIVATE (testing only)"
        } else {
            "deny loopback/private/special-use"
        }
    );
    if settings.allowed_ports.is_empty() {
        println!("  allowed_ports : all");
    } else {
        println!("  allowed_ports : {:?}", settings.allowed_ports);
    }
    println!(
        "  dns           : {}",
        if settings.dns.servers.is_empty() {
            "system resolver".to_string()
        } else {
            settings.dns.servers.join(", ")
        }
    );
    println!("  max_conns     : {}", settings.limits.max_connections);
    println!(
        "  max_streams   : {} per session",
        settings.limits.max_streams_per_session
    );
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

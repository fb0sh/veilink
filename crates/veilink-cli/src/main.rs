//! Veilink — a privacy-focused, encrypted HTTP/HTTPS proxy.
//!
//! This binary is the single entry point for every Veilink role:
//!
//! ```text
//! veilink client --config client.yaml     # run the local proxy
//! veilink server --config server.yaml     # run the remote relay
//! veilink keygen                          # generate an authentication key
//! veilink check  --config client.yaml     # validate a configuration file
//! ```

#![forbid(unsafe_code)]

mod commands;
mod logging;
mod reload;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Veilink — a privacy-focused, encrypted HTTP/HTTPS proxy.
#[derive(Debug, Parser)]
#[command(
    name = "veilink",
    version,
    about = "Veilink — a privacy-focused, encrypted HTTP/HTTPS proxy",
    long_about = "Veilink is a client/server encrypted HTTP and HTTPS proxy.\n\n\
                  The client listens locally, decides per request whether the target is forwarded\n\
                  through your VPS or connected directly, and carries forwarded traffic inside the\n\
                  authenticated VLP/1 protocol with per-frame forward-secret encryption.",
    propagate_version = true,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the local proxy client.
    Client(commands::client::ClientArgs),
    /// Run the remote relay server.
    Server(commands::server::ServerArgs),
    /// Generate a high-entropy authentication key.
    Keygen(commands::keygen::KeygenArgs),
    /// Validate a configuration file and exit.
    Check(commands::check::CheckArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(error) => {
            // Print the full cause chain, without ever including secret material.
            eprintln!("error: {error}");
            for cause in error.chain().skip(1) {
                eprintln!("  caused by: {cause}");
            }
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Command::Keygen(args) => {
            // keygen must never emit log records: the key is the output.
            commands::keygen::run(&args)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Client(args) => commands::client::run(args),
        Command::Server(args) => commands::server::run(args),
        Command::Check(args) => {
            logging::init(logging::InitOptions {
                default_level: "warn",
                ..logging::InitOptions::default()
            })?;
            let ok = commands::check::run(&args)?;
            Ok(if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
    }
}

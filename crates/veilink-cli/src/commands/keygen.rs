//! `veilink keygen` — generate a high-entropy authentication key.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use veilink_crypto::Psk;
use zeroize::Zeroizing;

/// Output encoding for the generated key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Encoding {
    /// Standard Base64URL without padding (default).
    Base64Url,
    /// Lower-case hexadecimal.
    Hex,
}

/// Arguments for `veilink keygen`.
#[derive(Debug, clap::Args)]
pub struct KeygenArgs {
    /// Output encoding.
    #[arg(long, value_enum, default_value_t = Encoding::Base64Url)]
    pub encoding: Encoding,
    /// Write the key to this file instead of standard output.
    ///
    /// The file is created with owner-only permissions (0600 on Unix). An existing file is never
    /// overwritten unless `--force` is given.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Overwrite an existing `--output` file.
    #[arg(long)]
    pub force: bool,
    /// Generate this many independent keys, one per line.
    #[arg(long, short = 'n', default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..=64))]
    pub count: u16,
    /// Print only the key, with no explanatory text. Implied by `--output`.
    #[arg(long)]
    pub quiet: bool,
}

/// Runs `veilink keygen`.
pub fn run(args: &KeygenArgs) -> Result<()> {
    let mut keys: Vec<Zeroizing<String>> = Vec::with_capacity(args.count as usize);
    for _ in 0..args.count {
        let psk =
            Psk::generate().context("failed to obtain randomness from the operating system")?;
        keys.push(render(&psk, args.encoding));
    }

    match &args.output {
        Some(path) => {
            write_key_file(path, &keys, args.force)?;
            if !args.quiet {
                // Never print the key itself when it was written to a file.
                println!(
                    "Wrote {} key{} to {} with mode 0600.",
                    keys.len(),
                    if keys.len() == 1 { "" } else { "s" },
                    path.display()
                );
                println!("Keep this file private and copy the key into both client.yaml and server.yaml.");
            }
        }
        None => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            if !args.quiet {
                eprintln!(
                    "# Veilink authentication key ({}-bit).\n\
                     # Place the same value in `key:` in both client.yaml and server.yaml.\n\
                     # Treat it like a password: anyone holding it can use your server.",
                    psk_bits(&keys)
                );
            }
            for key in &keys {
                writeln!(lock, "{}", key.as_str()).context("failed to write to standard output")?;
            }
            lock.flush().ok();
        }
    }
    Ok(())
}

fn psk_bits(keys: &[Zeroizing<String>]) -> usize {
    let _ = keys;
    veilink_crypto::psk::GENERATED_PSK_LEN * 8
}

fn render(psk: &Psk, encoding: Encoding) -> Zeroizing<String> {
    match encoding {
        Encoding::Base64Url => psk.to_base64url(),
        Encoding::Hex => {
            let mut out = String::with_capacity(psk.len() * 2);
            for byte in psk.as_bytes() {
                out.push_str(&format!("{byte:02x}"));
            }
            Zeroizing::new(out)
        }
    }
}

fn write_key_file(path: &Path, keys: &[Zeroizing<String>], force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "refusing to overwrite existing file `{}`; pass --force to replace it",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory `{}`", parent.display()))?;
        }
    }

    let mut body = Zeroizing::new(String::new());
    for key in keys {
        body.push_str(key);
        body.push('\n');
    }

    write_private_file(path, body.as_bytes())?;
    Ok(())
}

/// Writes `contents` to `path`, creating the file with owner-only permissions.
///
/// On Unix the file is created with mode `0600` from the start, so the key is never briefly
/// readable by other users of the machine. Windows inherits the ACL of the parent directory.
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create `{}`", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("failed to write `{}`", path.display()))?;
    file.sync_all().ok();
    Ok(())
}

//! The server's long-term identity.
//!
//! The identity is an X25519 key pair generated on first start and reused afterwards. It is *not*
//! used to encrypt anything: it exists so that a deployment has a stable, authenticated name that
//! survives restarts.
//!
//! What it is used for:
//!
//! * it is published inside the `SERVER_HELLO`, which is covered by the transcript and therefore by
//!   the PSK-bound confirmation MAC, so a client knows it is talking to the same server instance it
//!   talked to before;
//! * it is embedded in the generated self-signed TLS certificate, so an operator inspecting the
//!   certificate can correlate it with the log line that prints the identity fingerprint;
//! * a client may pin the fingerprint and refuse any other server, which turns "the operator
//!   replaced the VPS" from a silent event into a visible failure.
//!
//! ## Storage
//!
//! The private half is written to `<state_dir>/identity.key` in a small, explicit text format with
//! owner-only permissions. Loading refuses a file that is readable by group or others, because a
//! world-readable identity key is a misconfiguration that should be fixed rather than tolerated.
//!
//! ## Independence from session keys
//!
//! Nothing in the per-frame key schedule depends on this key, and this key is never derived from
//! session material. Losing it does not expose recorded traffic; stealing it does not let an
//! attacker decrypt frames, because every frame key came from an ephemeral exchange whose secrets
//! have already been erased.

use std::fmt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::x25519::IdentitySecret;
use crate::CryptoError;

/// File name used for the identity inside the state directory.
pub const IDENTITY_FILE: &str = "identity.key";

/// Header of the identity file format.
const IDENTITY_HEADER: &str = "VEILINK-IDENTITY-1";

/// Errors raised while loading, creating or storing the identity.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The state directory could not be created.
    #[error("cannot create the state directory `{}`: {source}", path.display())]
    CreateDir {
        /// Directory that could not be created.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The identity file could not be read.
    #[error("cannot read the identity file `{}`: {source}", path.display())]
    Read {
        /// File that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The identity file could not be written.
    #[error("cannot write the identity file `{}`: {source}", path.display())]
    Write {
        /// File that could not be written.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The identity file contents were not valid.
    #[error("identity file `{}` is not a valid Veilink identity: {reason}", path.display())]
    Malformed {
        /// File that failed to parse.
        path: PathBuf,
        /// Why it failed.
        reason: String,
    },
    /// The identity file has unsafe permissions.
    #[error(
        "identity file `{}` is readable by other users (mode {mode:o}); \
         run `chmod 600 {}` before starting the server",
        path.display(),
        path.display()
    )]
    InsecurePermissions {
        /// File with unsafe permissions.
        path: PathBuf,
        /// Observed mode bits.
        mode: u32,
    },
    /// The cryptographic layer refused the key material.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// A loaded server identity.
pub struct Identity {
    secret: IdentitySecret,
    fingerprint: [u8; 32],
    path: PathBuf,
    /// True when this process generated the identity rather than loading it.
    created: bool,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("fingerprint", &self.fingerprint_hex())
            .field("path", &self.path)
            .field("created", &self.created)
            .finish()
    }
}

impl Identity {
    /// Loads the identity from `state_dir`, creating it on first run.
    pub fn load_or_create(state_dir: &Path) -> Result<Self, IdentityError> {
        let path = state_dir.join(IDENTITY_FILE);
        if path.exists() {
            return Identity::load(&path);
        }
        std::fs::create_dir_all(state_dir).map_err(|source| IdentityError::CreateDir {
            path: state_dir.to_path_buf(),
            source,
        })?;
        let secret = IdentitySecret::generate()?;
        let identity = Identity::from_secret(secret, path.clone());
        identity.store()?;
        Ok(Identity {
            created: true,
            ..identity
        })
    }

    /// Loads an identity from an explicit path.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        check_permissions(path)?;
        let text = std::fs::read_to_string(path).map_err(|source| IdentityError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let mut lines = text.lines().filter(|l| !l.trim().is_empty());
        let header = lines.next().unwrap_or_default().trim();
        if header != IDENTITY_HEADER {
            return Err(IdentityError::Malformed {
                path: path.to_path_buf(),
                reason: format!("expected the header `{IDENTITY_HEADER}`"),
            });
        }
        let hex = lines
            .next()
            .ok_or_else(|| IdentityError::Malformed {
                path: path.to_path_buf(),
                reason: "missing the key material line".to_string(),
            })?
            .trim();
        if hex.len() != 64 {
            return Err(IdentityError::Malformed {
                path: path.to_path_buf(),
                reason: format!("expected 64 hex characters, found {}", hex.len()),
            });
        }
        let mut bytes = [0u8; 32];
        for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let text = std::str::from_utf8(chunk).map_err(|_| IdentityError::Malformed {
                path: path.to_path_buf(),
                reason: "key material is not ASCII hex".to_string(),
            })?;
            bytes[index] = u8::from_str_radix(text, 16).map_err(|_| IdentityError::Malformed {
                path: path.to_path_buf(),
                reason: "key material is not hex".to_string(),
            })?;
        }
        let secret = IdentitySecret::from_bytes(bytes)?;
        Ok(Identity::from_secret(secret, path.to_path_buf()))
    }

    fn from_secret(secret: IdentitySecret, path: PathBuf) -> Self {
        let fingerprint = fingerprint_of(&secret.public_bytes());
        Identity {
            secret,
            fingerprint,
            path,
            created: false,
        }
    }

    /// Writes the identity to disk with owner-only permissions.
    pub fn store(&self) -> Result<(), IdentityError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|source| IdentityError::CreateDir {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }
        let body = format!(
            "{IDENTITY_HEADER}\n{}\n",
            hex_encode(&*self.secret.to_bytes())
        );
        write_private(&self.path, body.as_bytes()).map_err(|source| IdentityError::Write {
            path: self.path.clone(),
            source,
        })
    }

    /// The long-term public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.secret.public_bytes()
    }

    /// The identity fingerprint: `SHA-256` of the public key.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// The fingerprint as lower-case hexadecimal.
    pub fn fingerprint_hex(&self) -> String {
        hex_encode(&self.fingerprint)
    }

    /// The fingerprint as a short, human-comparable string: the first four bytes in hex, in pairs
    /// separated by colons, as is conventional for certificate fingerprints.
    pub fn short_fingerprint(&self) -> String {
        self.fingerprint[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// The underlying key pair, for the transport that signs the TLS certificate.
    pub fn secret(&self) -> &IdentitySecret {
        &self.secret
    }

    /// Where the identity is stored.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True when this process created the identity rather than loading it.
    pub fn was_created(&self) -> bool {
        self.created
    }
}

/// Computes the fingerprint of an identity public key.
pub fn fingerprint_of(public: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"vlp/1 identity fingerprint");
    hasher.update(public);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Parses a user-supplied fingerprint pin, accepting `aa:bb:...`, `aabb...` or a full SHA-256 hex
/// fingerprint.
pub fn parse_fingerprint_pin(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input
        .chars()
        .filter(|c| *c != ':' && *c != '-' && !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    if cleaned.len() % 2 != 0 || cleaned.is_empty() {
        return Err("fingerprint must be an even number of hex characters".to_string());
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks_exact(2) {
        let text =
            std::str::from_utf8(chunk).map_err(|_| "fingerprint is not ASCII".to_string())?;
        bytes.push(
            u8::from_str_radix(text, 16)
                .map_err(|_| "fingerprint is not hexadecimal".to_string())?,
        );
    }
    // Accept the full 32-byte fingerprint, or a short prefix for convenience.
    if bytes.len() != 32 && bytes.len() < 4 {
        return Err(
            "fingerprint must be the full 64-character value or at least 4 bytes".to_string(),
        );
    }
    if bytes.len() > 32 {
        return Err("fingerprint is longer than a SHA-256 digest".to_string());
    }
    Ok(bytes)
}

/// Verifies an observed fingerprint against a pin, comparing only the pinned prefix.
pub fn fingerprint_matches_pin(pin: &[u8], observed: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    if pin.len() > observed.len() {
        return false;
    }
    observed[..pin.len()].ct_eq(pin).into()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).map_err(|source| IdentityError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(IdentityError::InsecurePermissions {
            path: path.to_path_buf(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), IdentityError> {
    Ok(())
}

fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_then_loads_the_same_identity() {
        let dir = tempfile::tempdir().unwrap();
        let first = Identity::load_or_create(dir.path()).unwrap();
        assert!(first.was_created());
        let fingerprint = first.fingerprint();

        let second = Identity::load_or_create(dir.path()).unwrap();
        assert!(!second.was_created());
        assert_eq!(second.fingerprint(), fingerprint);
        assert_eq!(second.public_bytes(), first.public_bytes());
    }

    #[test]
    fn identity_file_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::load_or_create(dir.path()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(identity.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "identity file must be owner-only");
        }
        assert!(identity.path().ends_with(IDENTITY_FILE));
    }

    #[test]
    #[cfg(unix)]
    fn refuses_a_world_readable_identity_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::load_or_create(dir.path()).unwrap();
        let path = identity.path().to_path_buf();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&path, permissions).unwrap();

        let error = Identity::load(&path).unwrap_err();
        assert!(matches!(error, IdentityError::InsecurePermissions { .. }));
        assert!(error.to_string().contains("chmod 600"));
    }

    /// Writes a file with owner-only permissions so that content checks are reached.
    fn write_private_0600(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn rejects_malformed_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.key");

        write_private_0600(&path, "not an identity\n");
        assert!(matches!(
            Identity::load(&path).unwrap_err(),
            IdentityError::Malformed { .. }
        ));

        write_private_0600(&path, &format!("{IDENTITY_HEADER}\n"));
        assert!(matches!(
            Identity::load(&path).unwrap_err(),
            IdentityError::Malformed { .. }
        ));

        write_private_0600(&path, &format!("{IDENTITY_HEADER}\nzzzz\n"));
        assert!(matches!(
            Identity::load(&path).unwrap_err(),
            IdentityError::Malformed { .. }
        ));

        write_private_0600(&path, &format!("{IDENTITY_HEADER}\n{}\n", "00".repeat(32)));
        // All-zero seeds are refused by the crypto layer.
        assert!(matches!(
            Identity::load(&path).unwrap_err(),
            IdentityError::Crypto(_)
        ));
    }

    #[test]
    fn fingerprints_are_stable_and_distinguishing() {
        let dir = tempfile::tempdir().unwrap();
        let a = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(a.fingerprint(), fingerprint_of(&a.public_bytes()));
        assert_eq!(a.fingerprint_hex().len(), 64);
        assert_eq!(a.short_fingerprint().len(), 11);

        assert_ne!(
            fingerprint_of(&[1u8; 32]),
            fingerprint_of(&[2u8; 32]),
            "different keys must have different fingerprints"
        );
    }

    #[test]
    fn fingerprint_pins_are_parsed_leniently_and_compared_exactly() {
        let full = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
        let pinned = parse_fingerprint_pin(full).unwrap();
        assert_eq!(pinned.len(), 32);
        let observed: [u8; 32] = pinned.clone().try_into().expect("32 bytes");
        assert!(fingerprint_matches_pin(&pinned, &observed));

        // Colons, dashes and upper case are accepted.
        let pretty = "AA:BB:CC:DD";
        let short = parse_fingerprint_pin(pretty).unwrap();
        assert_eq!(short, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(parse_fingerprint_pin("aabbccdd").is_ok());
        assert!(fingerprint_matches_pin(&short, &observed));

        // A different value does not match.
        let other = parse_fingerprint_pin("aabbccde").unwrap();
        assert!(!fingerprint_matches_pin(&other, &observed));

        assert!(parse_fingerprint_pin("").is_err());
        assert!(parse_fingerprint_pin("abc").is_err());
        assert!(parse_fingerprint_pin("zzzz").is_err());
        assert!(parse_fingerprint_pin(&"aa".repeat(40)).is_err());
    }

    #[test]
    fn debug_output_exposes_only_the_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let identity = Identity::load_or_create(dir.path()).unwrap();
        let text = format!("{identity:?}");
        let secret_hex = hex_encode(&*identity.secret().to_bytes());
        assert!(
            !text.contains(&secret_hex),
            "debug output leaked the private key"
        );
        assert!(text.contains(&identity.fingerprint_hex()));
    }
}

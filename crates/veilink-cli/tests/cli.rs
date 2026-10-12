//! End-to-end tests for the `veilink` command line interface.

use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use veilink_crypto::Psk;

const GOOD_KEY: &str = "9f8c1d2e3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5";

fn veilink() -> Command {
    Command::cargo_bin("veilink").expect("the veilink binary is built for tests")
}

#[test]
fn version_and_help_are_available() {
    veilink()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));

    veilink()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("keygen"))
        .stdout(predicate::str::contains("check"));
}

#[test]
fn keygen_prints_a_usable_key() {
    let output = veilink().arg("keygen").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let key = stdout.trim();
    assert_eq!(
        stdout.lines().count(),
        1,
        "stdout must contain only the key"
    );

    let psk = Psk::parse(key).expect("generated key must parse");
    assert_eq!(psk.len(), 32);

    // The key must not be echoed to stderr either.
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains(key), "stderr leaked the key");
}

#[test]
fn keygen_hex_encoding() {
    let output = veilink()
        .args(["keygen", "--encoding", "hex", "--quiet"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let key = stdout.trim();
    assert_eq!(key.len(), 64);
    assert!(key.bytes().all(|b| b.is_ascii_hexdigit()));
    Psk::parse(key).unwrap();
}

#[test]
fn keygen_writes_private_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("veilink.key");

    veilink()
        .args(["keygen", "--output"])
        .arg(&path)
        .assert()
        .success();

    let contents = std::fs::read_to_string(&path).unwrap();
    Psk::parse(contents.trim()).expect("written key must parse");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "key file must be owner-only");
    }

    // Refuses to clobber without --force.
    veilink()
        .args(["keygen", "--output"])
        .arg(&path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--force"));

    veilink()
        .args(["keygen", "--output"])
        .arg(&path)
        .arg("--force")
        .assert()
        .success();
}

#[test]
fn keygen_multiple_keys_are_distinct() {
    let output = veilink()
        .args(["keygen", "--count", "4", "--quiet"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let keys: Vec<&str> = stdout.lines().collect();
    assert_eq!(keys.len(), 4);
    let unique: std::collections::HashSet<&str> = keys.iter().copied().collect();
    assert_eq!(unique.len(), 4, "generated keys must be distinct");
    for key in keys {
        Psk::parse(key).unwrap();
    }
}

#[test]
fn check_accepts_a_valid_client_config() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.yaml");
    std::fs::write(
        &path,
        format!(
            "server: \"203.0.113.10:443\"\nkey: \"{GOOD_KEY}\"\nwhitelist:\n  - \"DOMAIN-SUFFIX,github.com\"\n"
        ),
    )
    .unwrap();

    veilink()
        .args(["check", "--config"])
        .arg(&path)
        .arg("--verbose")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "valid Veilink client configuration",
        ))
        .stdout(predicate::str::contains("DOMAIN-SUFFIX,github.com"))
        .stdout(predicate::str::contains(GOOD_KEY).not());
}

#[test]
fn check_reports_every_bad_rule() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.yaml");
    std::fs::write(
        &path,
        format!(
            "server: \"203.0.113.10:443\"\nkey: \"{GOOD_KEY}\"\nwhitelist:\n  - \"BOGUS,x\"\n  - \"CIDR,not-a-cidr\"\n"
        ),
    )
    .unwrap();

    veilink()
        .args(["check", "--config"])
        .arg(&path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("whitelist[0]"))
        .stderr(predicate::str::contains("whitelist[1]"));
}

#[test]
fn check_rejects_unknown_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.yaml");
    std::fs::write(
        &path,
        format!("server: \"203.0.113.10:443\"\nkey: \"{GOOD_KEY}\"\nmystery: 3\n"),
    )
    .unwrap();

    veilink()
        .args(["check", "--config"])
        .arg(&path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("mystery"));
}

#[test]
fn check_detects_server_config_and_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("server.yaml");
    std::fs::write(&path, format!("key: \"{GOOD_KEY}\"\n")).unwrap();

    veilink()
        .args(["check", "--config"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "valid Veilink server configuration",
        ));

    veilink()
        .args(["check", "--config"])
        .arg(dir.path().join("missing.yaml"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot read"));
}

#[test]
fn check_honours_explicit_type() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.yaml");
    std::fs::write(&path, format!("key: \"{GOOD_KEY}\"\n")).unwrap();

    // Forcing `server` succeeds because `key` alone is a valid server configuration.
    veilink()
        .args(["check", "--config"])
        .arg(&path)
        .args(["--type", "server"])
        .assert()
        .success();

    // Forcing `client` fails because `server` is missing.
    veilink()
        .args(["check", "--config"])
        .arg(&path)
        .args(["--type", "client"])
        .assert()
        .failure();
}

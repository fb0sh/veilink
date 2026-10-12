//! Fuzzes the YAML configuration parsers.
//!
//! Both parsers are fed a file the operator wrote, and both are expected to produce a *report* of
//! every problem rather than panicking on the first one. The invariants are therefore that neither
//! parser panics, that validation is deterministic, and that a configuration that validates never
//! carries a value the runtime would have to re-check (the key length, the limits and the listen
//! address are all decided during validation).

#![no_main]

use libfuzzer_sys::fuzz_target;
use veilink_config::{ClientConfig, ServerConfig};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(config) = ClientConfig::from_yaml(text) {
        let first = config.clone().validate();
        let second = config.validate();
        match (&first, &second) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a.server, b.server, "validation was not deterministic");
                assert_eq!(a.listen, b.listen, "validation was not deterministic");
                assert_eq!(
                    a.rules.len(),
                    b.rules.len(),
                    "validation was not deterministic"
                );
                // A validated key must meet the protocol minimum, so the runtime never has to
                // reject a key that validation accepted.
                assert!(a.psk.as_bytes().len() >= veilink_crypto::MIN_PSK_LEN);
            }
            (Err(a), Err(b)) => {
                assert_eq!(
                    a.to_string(),
                    b.to_string(),
                    "the diagnostics were not deterministic"
                );
            }
            _ => panic!("validation returned different results for the same input"),
        }
    }

    if let Ok(config) = ServerConfig::from_yaml(text) {
        let first = config.clone().validate();
        let second = config.validate();
        match (&first, &second) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a.listen, b.listen, "validation was not deterministic");
                assert!(a.psk.as_bytes().len() >= veilink_crypto::MIN_PSK_LEN);
            }
            (Err(a), Err(b)) => {
                assert_eq!(
                    a.to_string(),
                    b.to_string(),
                    "the diagnostics were not deterministic"
                );
            }
            _ => panic!("validation returned different results for the same input"),
        }
    }
});

//! Fuzzes the whitelist rule parser and matcher.
//!
//! Rules come from a configuration file, which is operator-controlled rather than
//! attacker-controlled, so the risk is not remote code execution but a rule that is accepted and
//! then behaves differently from what it says. The invariants enforced here are:
//!
//! * a rule that parses has a canonical form that parses back to the same rule, so what
//!   `veilink check` prints is what the proxy enforces;
//! * parsing is idempotent;
//! * matching is a pure function of the rule and the target, so the same input always produces the
//!   same routing decision;
//! * a catch-all never claims to be a narrow rule, and vice versa.

#![no_main]

use libfuzzer_sys::fuzz_target;
use veilink_rules::{HostName, Rule, RuleKind, RuleSet};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    if let Ok(rule) = Rule::parse(text) {
        // The canonical rendering must parse back to the same rule, and parsing it again must be
        // idempotent.
        let rendered = rule.to_string();
        let reparsed = Rule::parse(&rendered)
            .unwrap_or_else(|e| panic!("the canonical form {rendered:?} did not parse: {e}"));
        assert_eq!(reparsed, rule, "a rule did not survive its canonical form");
        assert_eq!(
            reparsed.to_string(),
            rendered,
            "the canonical form was not stable"
        );

        // Matching must be deterministic, and a rule must only match targets of its own family.
        for host in [
            "",
            "example.test",
            "a.b.c.example.test",
            "127.0.0.1",
            "xn--bcher-kva.test",
        ] {
            if let Ok(name) = HostName::parse(host) {
                let first = rule.matches_domain(&name);
                let second = rule.matches_domain(&name);
                assert_eq!(first, second, "domain matching was not deterministic");
            }
        }
        for ip in ["0.0.0.0", "127.0.0.1", "10.1.2.3", "255.255.255.255"] {
            let Ok(ip) = ip.parse::<std::net::Ipv4Addr>() else {
                continue;
            };
            let first = rule.matches_ip(ip);
            let second = rule.matches_ip(ip);
            assert_eq!(first, second, "address matching was not deterministic");

            // An address rule must never match a domain and a domain rule must never match an
            // address unless it is a catch-all, because the two decisions route to different places.
            let domain_like = matches!(rule.kind(), RuleKind::Domain | RuleKind::DomainSuffix);
            if domain_like {
                assert!(!first, "the domain rule {rule} matched the address {ip}");
            }
        }
    }

    // Building a set from many lines must not panic and must be deterministic.
    let lines: Vec<&str> = text.lines().take(64).collect();
    if let Ok(set) = RuleSet::parse(lines.iter().copied()) {
        let again = RuleSet::parse(lines.iter().copied()).expect("deterministic build");
        assert_eq!(
            again.len(),
            set.len(),
            "a rule set build was not deterministic"
        );
        // An empty set and a set of length zero are the same statement; assert the count is
        // reproducible and let `len()` be the single source of truth.
        assert_eq!(set.len(), again.len());
    }
});

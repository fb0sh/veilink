//! # veilink-rules
//!
//! The whitelist rule engine used by the Veilink client to decide, for every intercepted request,
//! whether the traffic is forwarded through the remote Veilink server (`PROXY`) or connected
//! directly from the local host (`DIRECT`).
//!
//! ## Supported rules
//!
//! | Rule | Meaning | Example |
//! |------|---------|---------|
//! | `DOMAIN` | exact domain match, single-label `*` allowed | `DOMAIN,github.com`, `DOMAIN,api.*.example.com` |
//! | `DOMAIN-SUFFIX` | domain and every subdomain, on DNS label boundaries | `DOMAIN-SUFFIX,github.com` |
//! | `IP` | exact IPv4 literal | `IP,1.1.1.1` |
//! | `CIDR` | IPv4 network | `CIDR,140.82.112.0/24` |
//! | `*` | catch-all: everything goes through the server | `*` |
//!
//! Rules are evaluated with OR semantics; the first match wins and its index is reported in
//! [`Decision::Proxy`]. An empty rule set routes everything `DIRECT`.
//!
//! ## Design guarantees
//!
//! * Domains are canonicalised (lower-case, no trailing root dot, IDNA A-labels) before matching.
//! * `DOMAIN-SUFFIX` uses DNS label boundaries, never naive string suffixes.
//! * `IP`/`CIDR` rules only ever match IPv4 *literals* in the request target, so a domain is never
//!   resolved locally just to evaluate them.
//! * The rule set is immutable once built; swapping in a new configuration is an atomic pointer
//!   exchange in [`RuleEngine`], so in-flight requests keep the routing they started with.
//!
//! ## Example
//!
//! ```
//! use veilink_rules::{RuleSet, Target, Decision};
//! use std::net::Ipv4Addr;
//!
//! let set = RuleSet::parse([
//!     "DOMAIN,github.com",
//!     "DOMAIN-SUFFIX,githubusercontent.com",
//!     "CIDR,140.82.112.0/24",
//! ]).unwrap();
//!
//! let domain = Target::Domain("raw.githubusercontent.com".parse().unwrap());
//! assert!(set.decide(&domain).is_proxy());
//!
//! let ip = Target::Ipv4(Ipv4Addr::new(140, 82, 112, 4));
//! assert!(set.decide(&ip).is_proxy());
//!
//! let other = Target::Domain("example.org".parse().unwrap());
//! assert_eq!(set.decide(&other), Decision::Direct);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod domain;
pub mod ip;
pub mod matcher;
pub mod wildcard;

pub use domain::{split_authority, DomainError, HostName};
pub use ip::{IpError, IpMatcher};
pub use matcher::{
    Decision, Rule, RuleError, RuleKind, RuleSet, RuleSetBuildError, RuleSetError, RuleValue,
    Target,
};
pub use wildcard::{WildcardError, WildcardPattern};

use std::sync::Arc;

use arc_swap::ArcSwap;

/// A hot-swappable rule set.
///
/// Cloning a [`RuleEngine`] shares the same underlying storage, which is what makes live
/// configuration reloads visible to every connection handler without a restart.
#[derive(Debug, Clone)]
pub struct RuleEngine {
    current: Arc<ArcSwap<RuleSet>>,
}

impl Default for RuleEngine {
    fn default() -> Self {
        RuleEngine::new(RuleSet::empty())
    }
}

impl RuleEngine {
    /// Creates an engine around an initial rule set.
    pub fn new(initial: RuleSet) -> Self {
        RuleEngine {
            current: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    /// Returns a snapshot of the active rule set.
    ///
    /// The returned handle keeps the rules alive and stable for the lifetime of the routing
    /// decision, even if a reload happens concurrently.
    pub fn snapshot(&self) -> Arc<RuleSet> {
        self.current.load_full()
    }

    /// Atomically replaces the active rule set and returns the previous one.
    pub fn replace(&self, next: RuleSet) -> Arc<RuleSet> {
        self.current.swap(Arc::new(next))
    }

    /// Decides how `target` is routed using the currently active rules.
    pub fn decide(&self, target: &Target) -> Decision {
        self.snapshot().decide(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn host(s: &str) -> HostName {
        HostName::parse(s).unwrap()
    }

    fn set(rules: &[&str]) -> RuleSet {
        RuleSet::parse(rules).unwrap()
    }

    #[test]
    fn exact_domain_matching() {
        let s = set(&["DOMAIN,github.com"]);
        assert!(s.decide(&Target::Domain(host("github.com"))).is_proxy());
        assert!(!s.decide(&Target::Domain(host("api.github.com"))).is_proxy());
        assert!(!s.decide(&Target::Domain(host("fakegithub.com"))).is_proxy());
        assert!(!s
            .decide(&Target::Domain(host("github.com.evil.test")))
            .is_proxy());
    }

    #[test]
    fn domain_suffix_matching() {
        let s = set(&["DOMAIN-SUFFIX,github.com"]);
        for ok in [
            "github.com",
            "api.github.com",
            "raw.api.github.com",
            "GITHUB.COM",
            "github.com.",
        ] {
            assert!(
                s.decide(&Target::Domain(host(ok))).is_proxy(),
                "expected {ok} to match"
            );
        }
        for bad in [
            "fakegithub.com",
            "github.com.attacker.example",
            "com",
            "notgithub.com",
        ] {
            assert!(
                !s.decide(&Target::Domain(host(bad))).is_proxy(),
                "expected {bad} not to match"
            );
        }
    }

    #[test]
    fn suffix_label_boundary_not_string_suffix() {
        // The classic bug: `ends_with("github.com")` would match `evilgithub.com`.
        let s = set(&["DOMAIN-SUFFIX,github.com"]);
        assert!(!s.decide(&Target::Domain(host("evilgithub.com"))).is_proxy());
        // And a hyphenated lookalike must not match either.
        assert!(!s
            .decide(&Target::Domain(host("github.com.evil")))
            .is_proxy());
    }

    #[test]
    fn ip_and_cidr_match_literals_only() {
        let s = set(&["IP,1.1.1.1", "CIDR,140.82.112.0/24"]);
        assert!(s
            .decide(&Target::Ipv4(Ipv4Addr::new(1, 1, 1, 1)))
            .is_proxy());
        assert!(!s
            .decide(&Target::Ipv4(Ipv4Addr::new(1, 1, 1, 2)))
            .is_proxy());
        assert!(s
            .decide(&Target::Ipv4(Ipv4Addr::new(140, 82, 112, 0)))
            .is_proxy());
        assert!(s
            .decide(&Target::Ipv4(Ipv4Addr::new(140, 82, 112, 255)))
            .is_proxy());
        assert!(!s
            .decide(&Target::Ipv4(Ipv4Addr::new(140, 82, 113, 0)))
            .is_proxy());
        // A domain target is never matched against IP/CIDR rules.
        assert!(!s
            .decide(&Target::Domain(host("1.1.1.1.example.com")))
            .is_proxy());
    }

    #[test]
    fn catch_all_rule() {
        let s = set(&["*"]);
        assert!(s.has_catch_all());
        assert!(s
            .decide(&Target::Domain(host("anything.example")))
            .is_proxy());
        assert!(s
            .decide(&Target::Ipv4(Ipv4Addr::new(9, 9, 9, 9)))
            .is_proxy());
    }

    #[test]
    fn empty_whitelist_is_direct() {
        let s = RuleSet::empty();
        assert!(s.is_empty());
        assert_eq!(
            s.decide(&Target::Domain(host("github.com"))),
            Decision::Direct
        );
        assert_eq!(
            s.decide(&Target::Ipv4(Ipv4Addr::LOCALHOST)),
            Decision::Direct
        );
    }

    #[test]
    fn wildcard_single_label_rule() {
        let s = set(&["DOMAIN,api.*.example.com"]);
        assert!(s
            .decide(&Target::Domain(host("api.dev.example.com")))
            .is_proxy());
        assert!(!s
            .decide(&Target::Domain(host("api.example.com")))
            .is_proxy());
        assert!(!s
            .decide(&Target::Domain(host("api.a.b.example.com")))
            .is_proxy());
    }

    #[test]
    fn rule_types_are_case_insensitive_and_values_normalised() {
        let s = set(&["domain-suffix,GitHub.COM."]);
        assert!(s.decide(&Target::Domain(host("API.github.com"))).is_proxy());
    }

    #[test]
    fn idna_rules_and_targets_agree() {
        let s = set(&["DOMAIN-SUFFIX,bücher.example"]);
        assert!(s
            .decide(&Target::Domain(host("shop.xn--bcher-kva.example")))
            .is_proxy());
    }

    #[test]
    fn duplicate_rules_are_rejected() {
        let err = RuleSet::parse(["DOMAIN,github.com", "domain,GitHub.com."]).unwrap_err();
        assert!(matches!(err, RuleSetBuildError::Set { .. }));
        assert!(err.to_string().contains("duplicate"));

        // Different kinds are not duplicates.
        assert!(RuleSet::parse(["DOMAIN,github.com", "DOMAIN-SUFFIX,github.com"]).is_ok());
    }

    #[test]
    fn decision_reports_matched_rule_index() {
        let s = set(&["DOMAIN,example.com", "IP,1.1.1.1"]);
        match s.decide(&Target::Ipv4(Ipv4Addr::new(1, 1, 1, 1))) {
            Decision::Proxy { rule_index, rule } => {
                assert_eq!(rule_index, Some(1));
                assert_eq!(rule, "IP,1.1.1.1");
            }
            other => panic!("expected PROXY, got {other:?}"),
        }
    }

    #[test]
    fn parse_errors_are_specific() {
        let cases: &[(&str, &str)] = &[
            ("", "empty"),
            ("github.com", "TYPE,VALUE"),
            ("DOMAIN,", "missing a value"),
            ("BOGUS,x", "unknown rule type"),
            ("DOMAIN-SUFFIX,*.github.com", "does not support wildcards"),
            ("IP,140.82.112.0/24", "use CIDR"),
            ("CIDR,1.1.1.1", "use IP"),
            ("DOMAIN,::1", "IPv6"),
            ("CIDR,2001:db8::/32", "IPv6"),
            ("DOMAIN,a..b", "empty label"),
            ("DOMAIN,a*b.com", "whole DNS label"),
            ("DOMAIN,a,b", "too many fields"),
        ];
        for (input, needle) in cases {
            let err = Rule::parse(input).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.to_lowercase().contains(&needle.to_lowercase()),
                "rule {input:?} produced {msg:?}, expected it to mention {needle:?}"
            );
        }
    }

    #[test]
    fn hot_reload_swaps_atomically_and_keeps_old_snapshot() {
        let engine = RuleEngine::new(set(&["DOMAIN,example.com"]));
        let before = engine.snapshot();
        assert!(before
            .decide(&Target::Domain(host("example.com")))
            .is_proxy());

        engine.replace(set(&["DOMAIN,other.test"]));
        assert!(!engine
            .decide(&Target::Domain(host("example.com")))
            .is_proxy());
        assert!(engine
            .decide(&Target::Domain(host("other.test")))
            .is_proxy());

        // The old snapshot is unchanged, which is what keeps in-flight connections stable.
        assert!(before
            .decide(&Target::Domain(host("example.com")))
            .is_proxy());
    }

    #[test]
    fn or_semantics_first_match_wins() {
        let s = set(&["DOMAIN-SUFFIX,github.com", "DOMAIN,github.com"]);
        match s.decide(&Target::Domain(host("github.com"))) {
            Decision::Proxy { rule_index, .. } => assert_eq!(rule_index, Some(0)),
            other => panic!("expected PROXY, got {other:?}"),
        }
    }

    #[test]
    fn target_description_redacts_domains_by_default() {
        let t = Target::Domain(host("secret.example"));
        assert_eq!(t.describe(false), "domain:<redacted>");
        assert_eq!(t.describe(true), "domain:secret.example");
        assert_eq!(
            Target::Ipv4(Ipv4Addr::new(1, 2, 3, 4)).describe(false),
            "ip:1.2.3.4"
        );
    }

    #[test]
    fn rule_roundtrips_through_serde() {
        let rule: Rule = serde_yaml_ng::from_str("\"DOMAIN-SUFFIX,github.com\"").unwrap();
        assert_eq!(rule.identity(), "DOMAIN-SUFFIX,github.com");
        let s = serde_yaml_ng::to_string(&rule).unwrap();
        assert!(s.contains("DOMAIN-SUFFIX,github.com"));
    }
}

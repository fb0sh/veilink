//! The whitelist rule set: parsing, validation and matching.
//!
//! Matching is a pure function of the *target form*:
//!
//! * a **domain** target is only ever compared against `DOMAIN`, `DOMAIN-SUFFIX` and `*` rules;
//! * an **IPv4 literal** target is only ever compared against `IP`, `CIDR` and `*` rules.
//!
//! This mirrors the privacy requirement that a whitelisted domain must be handed to the remote
//! resolver verbatim: the client never pre-resolves a domain merely to evaluate `IP`/`CIDR` rules.

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::domain::{DomainError, HostName};
use crate::ip::{IpError, IpMatcher};
use crate::wildcard::{WildcardError, WildcardPattern};

/// The kind of a whitelist rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RuleKind {
    /// Exact domain match (`DOMAIN,github.com`).
    Domain,
    /// Domain and all of its subdomains (`DOMAIN-SUFFIX,github.com`).
    DomainSuffix,
    /// Exact IPv4 match (`IP,1.1.1.1`).
    Ip,
    /// IPv4 network match (`CIDR,140.82.112.0/24`).
    Cidr,
    /// Catch-all (`*`).
    All,
}

impl RuleKind {
    /// The canonical upper-case name of this rule kind.
    pub fn as_str(self) -> &'static str {
        match self {
            RuleKind::Domain => "DOMAIN",
            RuleKind::DomainSuffix => "DOMAIN-SUFFIX",
            RuleKind::Ip => "IP",
            RuleKind::Cidr => "CIDR",
            RuleKind::All => "*",
        }
    }
}

impl fmt::Display for RuleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RuleKind {
    type Err = RuleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_uppercase().as_str() {
            "DOMAIN" => Ok(RuleKind::Domain),
            "DOMAIN-SUFFIX" => Ok(RuleKind::DomainSuffix),
            "IP" => Ok(RuleKind::Ip),
            "CIDR" => Ok(RuleKind::Cidr),
            "*" => Ok(RuleKind::All),
            other => Err(RuleError::UnknownRuleType {
                rule: s.trim().to_string(),
                kind: other.to_string(),
            }),
        }
    }
}

/// The compiled payload of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleValue {
    /// `DOMAIN` with no wildcard label.
    Host(HostName),
    /// `DOMAIN` with at least one `*` label.
    Wildcard(WildcardPattern),
    /// `DOMAIN-SUFFIX` domain.
    Suffix(HostName),
    /// `IP` or `CIDR`.
    Ip(IpMatcher),
    /// `*`.
    All,
}

impl RuleValue {
    fn canonical(&self) -> String {
        match self {
            RuleValue::Host(h) => h.to_string(),
            RuleValue::Wildcard(w) => w.to_string(),
            RuleValue::Suffix(s) => s.to_string(),
            RuleValue::Ip(i) => i.to_string(),
            RuleValue::All => "*".to_string(),
        }
    }
}

/// A single parsed whitelist rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    kind: RuleKind,
    value: RuleValue,
    source: String,
}

impl Rule {
    /// Parses a rule from its textual form, for example `DOMAIN-SUFFIX,github.com`.
    pub fn parse(input: &str) -> Result<Self, RuleError> {
        let source = input.trim().to_string();
        if source.is_empty() {
            return Err(RuleError::Empty);
        }
        // Bare `*` is the catch-all rule.
        if source == "*" {
            return Ok(Rule {
                kind: RuleKind::All,
                value: RuleValue::All,
                source,
            });
        }
        let (kind_part, value_part) =
            source
                .split_once(',')
                .ok_or_else(|| RuleError::MissingSeparator {
                    rule: source.clone(),
                })?;
        let kind_part = kind_part.trim();
        let value_part = value_part.trim();
        if value_part.is_empty() {
            return Err(RuleError::EmptyValue {
                kind: kind_part.to_string(),
            });
        }
        // A value may itself contain a comma only by mistake; reject it explicitly.
        if value_part.contains(',') {
            return Err(RuleError::TooManyFields {
                rule: source.clone(),
            });
        }
        let kind = RuleKind::from_str(kind_part)?;
        // IPv6 literals are rejected explicitly for every rule type so that the operator gets an
        // actionable message instead of a domain syntax error.
        if kind != RuleKind::All && value_part.contains(':') {
            return Err(RuleError::Ip {
                value: value_part.to_string(),
                source: IpError::Ipv6Unsupported {
                    value: value_part.to_string(),
                },
            });
        }
        let value = match kind {
            RuleKind::Domain => {
                let pattern = WildcardPattern::parse(value_part)
                    .map_err(|e| RuleError::from_wildcard(value_part, e))?;
                if pattern.is_concrete() {
                    RuleValue::Host(
                        HostName::parse(value_part)
                            .map_err(|e| RuleError::from_domain(value_part, e))?,
                    )
                } else {
                    RuleValue::Wildcard(pattern)
                }
            }
            RuleKind::DomainSuffix => {
                if value_part.contains('*') {
                    return Err(RuleError::WildcardNotAllowed {
                        kind: "DOMAIN-SUFFIX".to_string(),
                        value: value_part.to_string(),
                    });
                }
                RuleValue::Suffix(
                    HostName::parse(value_part)
                        .map_err(|e| RuleError::from_domain(value_part, e))?,
                )
            }
            RuleKind::Ip => {
                if value_part.contains('/') {
                    return Err(RuleError::KindMismatch {
                        kind: "IP".to_string(),
                        value: value_part.to_string(),
                        hint: "use CIDR for network ranges".to_string(),
                    });
                }
                let m = IpMatcher::parse_host(value_part)
                    .map_err(|e| RuleError::from_ip(value_part, e))?;
                if !matches!(m, IpMatcher::Exact(_)) {
                    return Err(RuleError::KindMismatch {
                        kind: "IP".to_string(),
                        value: value_part.to_string(),
                        hint: "use CIDR for network ranges".to_string(),
                    });
                }
                RuleValue::Ip(m)
            }
            RuleKind::Cidr => {
                if !value_part.contains('/') {
                    return Err(RuleError::KindMismatch {
                        kind: "CIDR".to_string(),
                        value: value_part.to_string(),
                        hint: "use IP for a single address".to_string(),
                    });
                }
                let m = IpMatcher::parse_network(value_part)
                    .map_err(|e| RuleError::from_ip(value_part, e))?;
                if !matches!(m, IpMatcher::Network(_)) {
                    return Err(RuleError::KindMismatch {
                        kind: "CIDR".to_string(),
                        value: value_part.to_string(),
                        hint: "use IP for a single address".to_string(),
                    });
                }
                RuleValue::Ip(m)
            }
            RuleKind::All => {
                if value_part != "*" {
                    return Err(RuleError::KindMismatch {
                        kind: "*".to_string(),
                        value: value_part.to_string(),
                        hint: "the catch-all rule is written as a bare `*`".to_string(),
                    });
                }
                RuleValue::All
            }
        };
        Ok(Rule {
            kind,
            value,
            source,
        })
    }

    /// The kind of this rule.
    pub fn kind(&self) -> RuleKind {
        self.kind
    }

    /// The compiled value of this rule.
    pub fn value(&self) -> &RuleValue {
        &self.value
    }

    /// The exact text the user wrote (trimmed).
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Canonical identity of the rule, used for duplicate detection.
    ///
    /// `DOMAIN,GitHub.com` and `domain,github.com.` share the same identity.
    pub fn identity(&self) -> String {
        format!("{},{}", self.kind.as_str(), self.value.canonical())
    }

    /// True when this rule is the catch-all `*`.
    pub fn is_catch_all(&self) -> bool {
        matches!(self.value, RuleValue::All)
    }

    /// Evaluates the rule against a domain target.
    pub fn matches_domain(&self, host: &HostName) -> bool {
        match &self.value {
            RuleValue::All => true,
            RuleValue::Host(h) => h == host,
            RuleValue::Wildcard(p) => p.matches(host),
            RuleValue::Suffix(s) => host.is_subdomain_of(s),
            RuleValue::Ip(_) => false,
        }
    }

    /// Evaluates the rule against an IPv4 literal target.
    pub fn matches_ip(&self, ip: Ipv4Addr) -> bool {
        match &self.value {
            RuleValue::All => true,
            RuleValue::Ip(m) => m.matches(ip),
            _ => false,
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.source)
    }
}

impl FromStr for Rule {
    type Err = RuleError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Rule::parse(s)
    }
}

impl<'de> Deserialize<'de> for Rule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Rule::parse(&raw).map_err(serde::de::Error::custom)
    }
}

impl Serialize for Rule {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.source)
    }
}

/// A routing target extracted from a proxy request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A domain name that must be resolved remotely when the rule matches.
    Domain(HostName),
    /// An IPv4 literal that needs no resolution.
    Ipv4(Ipv4Addr),
}

impl Target {
    /// True when the target is a domain name.
    pub fn is_domain(&self) -> bool {
        matches!(self, Target::Domain(_))
    }

    /// Renders the target for logs. Domains are only included when the caller opts in.
    pub fn describe(&self, include_domain: bool) -> String {
        match self {
            Target::Domain(h) if include_domain => format!("domain:{h}"),
            Target::Domain(_) => "domain:<redacted>".to_string(),
            Target::Ipv4(ip) => format!("ip:{ip}"),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Domain(h) => write!(f, "{h}"),
            Target::Ipv4(ip) => write!(f, "{ip}"),
        }
    }
}

/// The routing decision for a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Forward through the Veilink server.
    Proxy {
        /// Index of the rule that matched, or `None` when the rule set was empty and the default
        /// catch-all applied.
        rule_index: Option<usize>,
        /// Canonical form of the matched rule.
        rule: String,
    },
    /// Connect directly from the client host.
    Direct,
}

impl Decision {
    /// True when the request must be forwarded through the server.
    pub fn is_proxy(&self) -> bool {
        matches!(self, Decision::Proxy { .. })
    }

    /// A short, loggable label: `PROXY` or `DIRECT`.
    pub fn label(&self) -> &'static str {
        if self.is_proxy() {
            "PROXY"
        } else {
            "DIRECT"
        }
    }
}

/// An immutable, atomically swappable set of whitelist rules.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
    /// Map from canonical rule identity to its position, for duplicate detection.
    identities: HashMap<String, usize>,
}

/// Errors raised when building a [`RuleSet`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleSetError {
    /// The same rule appeared twice.
    #[error(
        "duplicate rule: `{duplicate}` (first defined at index {first}, repeated at index {second})"
    )]
    Duplicate {
        /// Canonical identity of the duplicated rule.
        duplicate: String,
        /// Index of the first occurrence.
        first: usize,
        /// Index of the repeated occurrence.
        second: usize,
    },
}

impl RuleSet {
    /// Builds a rule set, rejecting duplicates.
    pub fn new(rules: Vec<Rule>) -> Result<Self, RuleSetError> {
        let mut identities = HashMap::with_capacity(rules.len());
        for (idx, rule) in rules.iter().enumerate() {
            let id = rule.identity();
            if let Some(&first) = identities.get(&id) {
                return Err(RuleSetError::Duplicate {
                    duplicate: id,
                    first,
                    second: idx,
                });
            }
            identities.insert(id, idx);
        }
        Ok(RuleSet { rules, identities })
    }

    /// Parses a list of textual rules.
    pub fn parse<I, S>(rules: I) -> Result<Self, RuleSetBuildError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut parsed = Vec::new();
        for (index, raw) in rules.into_iter().enumerate() {
            let rule = Rule::parse(raw.as_ref()).map_err(|source| RuleSetBuildError::Rule {
                index,
                source: Box::new(source),
            })?;
            parsed.push(rule);
        }
        RuleSet::new(parsed).map_err(|source| RuleSetBuildError::Set {
            source: Box::new(source),
        })
    }

    /// An empty rule set: every request is `DIRECT`.
    pub fn empty() -> Self {
        RuleSet::default()
    }

    /// The rules in declaration order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Looks up the position of a rule by its canonical identity.
    ///
    /// Because the set rejects duplicates, this is a total function of the rule identity.
    pub fn identity_index(&self, identity: &str) -> Option<usize> {
        self.identities.get(identity).copied()
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// True when the set contains no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// True when the set contains a bare `*` catch-all rule.
    pub fn has_catch_all(&self) -> bool {
        self.rules.iter().any(Rule::is_catch_all)
    }

    /// Matches a target against the rule set, returning the first matching rule.
    pub fn match_target(&self, target: &Target) -> Option<(usize, &Rule)> {
        let found = match target {
            Target::Domain(host) => self
                .rules
                .iter()
                .enumerate()
                .find(|(_, r)| r.matches_domain(host)),
            Target::Ipv4(ip) => self
                .rules
                .iter()
                .enumerate()
                .find(|(_, r)| r.matches_ip(*ip)),
        };
        found
    }

    /// Decides how a target must be routed.
    ///
    /// An empty rule set routes everything `DIRECT`; any matching rule routes the request through
    /// the server. Rules combine with OR semantics.
    pub fn decide(&self, target: &Target) -> Decision {
        match self.match_target(target) {
            Some((rule_index, rule)) => Decision::Proxy {
                rule_index: Some(rule_index),
                rule: rule.identity(),
            },
            None => Decision::Direct,
        }
    }
}

/// Errors raised while parsing a whole rule list.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleSetBuildError {
    /// A single rule failed to parse.
    #[error("whitelist[{index}]: {source}")]
    Rule {
        /// Position of the faulty rule in the whitelist.
        index: usize,
        /// The underlying parse error.
        #[source]
        source: Box<RuleError>,
    },
    /// The list as a whole was rejected.
    #[error("{source}")]
    Set {
        /// The underlying set error.
        #[source]
        source: Box<RuleSetError>,
    },
}

/// Errors raised while parsing a single rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    /// The rule text was empty.
    #[error("rule is empty")]
    Empty,
    /// The rule did not contain a `,` separator.
    #[error("rule `{rule}` must be written as `TYPE,VALUE` (for example `DOMAIN,github.com`) or as a bare `*`")]
    MissingSeparator {
        /// The offending rule.
        rule: String,
    },
    /// The value part was empty.
    #[error("rule type `{kind}` is missing a value")]
    EmptyValue {
        /// The rule type.
        kind: String,
    },
    /// More than one comma was present.
    #[error("rule `{rule}` has too many fields; expected exactly `TYPE,VALUE`")]
    TooManyFields {
        /// The offending rule.
        rule: String,
    },
    /// The rule type is not recognised.
    #[error("rule `{rule}`: unknown rule type `{kind}`; expected one of DOMAIN, DOMAIN-SUFFIX, IP, CIDR or `*`")]
    UnknownRuleType {
        /// The offending rule.
        rule: String,
        /// The offending type.
        kind: String,
    },
    /// A wildcard was used where it is not supported.
    #[error("`{kind}` does not support wildcards (value `{value}`)")]
    WildcardNotAllowed {
        /// The rule type.
        kind: String,
        /// The offending value.
        value: String,
    },
    /// The value form did not match the declared kind.
    #[error("`{kind},{value}` is not valid: {hint}")]
    KindMismatch {
        /// The rule type.
        kind: String,
        /// The offending value.
        value: String,
        /// What the user probably meant.
        hint: String,
    },
    /// The domain was malformed.
    #[error("rule `{value}`: {source}")]
    Domain {
        /// The offending value.
        value: String,
        /// The underlying domain error.
        #[source]
        source: DomainError,
    },
    /// The IP or CIDR value was malformed.
    #[error("rule `{value}`: {source}")]
    Ip {
        /// The offending value.
        value: String,
        /// The underlying IP error.
        #[source]
        source: IpError,
    },
    /// A wildcard pattern was malformed.
    #[error("rule `{value}`: {source}")]
    Wildcard {
        /// The offending value.
        value: String,
        /// The underlying wildcard error.
        #[source]
        source: WildcardError,
    },
}

impl RuleError {
    fn from_domain(value: &str, source: DomainError) -> Self {
        RuleError::Domain {
            value: value.to_string(),
            source,
        }
    }

    fn from_ip(value: &str, source: IpError) -> Self {
        RuleError::Ip {
            value: value.to_string(),
            source,
        }
    }

    fn from_wildcard(value: &str, source: WildcardError) -> Self {
        match source {
            WildcardError::Domain(d) => RuleError::Domain {
                value: value.to_string(),
                source: d,
            },
            other => RuleError::Wildcard {
                value: value.to_string(),
                source: other,
            },
        }
    }
}

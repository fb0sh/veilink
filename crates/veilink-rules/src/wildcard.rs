//! Single-label wildcard patterns used by the `DOMAIN` rule type.
//!
//! A pattern such as `api.*.example.com` matches exactly one DNS label in the position occupied by
//! `*`. It does **not** match zero labels or several labels — multi-level matching is the job of
//! `DOMAIN-SUFFIX`.

use std::fmt;

use crate::domain::{DomainError, HostName, MAX_LABEL_LEN};

/// A domain pattern whose `*` components each match exactly one DNS label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WildcardPattern {
    labels: Vec<Label>,
    /// Canonical display form where `*` occupies the wildcard positions.
    canonical: String,
    wildcard_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Label {
    Literal(String),
    Any,
}

/// Errors raised when a wildcard pattern is malformed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WildcardError {
    /// The pattern had no labels.
    #[error("wildcard pattern is empty")]
    Empty,
    /// A `*` appeared inside a label rather than as the whole label (`a*b.com`).
    #[error("`*` must occupy a whole DNS label, found `{label}`")]
    PartialWildcard {
        /// The offending label.
        label: String,
    },
    /// The underlying domain was invalid.
    #[error(transparent)]
    Domain(#[from] DomainError),
}

impl WildcardPattern {
    /// Builds a pattern from a textual domain, which may contain `*` labels.
    pub fn parse(input: &str) -> Result<Self, WildcardError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(WildcardError::Empty);
        }
        let without_root = trimmed.strip_suffix('.').unwrap_or(trimmed);
        if without_root.is_empty() {
            return Err(WildcardError::Empty);
        }

        let mut labels = Vec::new();
        let mut canonical = String::with_capacity(without_root.len());
        let mut wildcard_count = 0usize;

        for (idx, raw) in without_root.split('.').enumerate() {
            if raw.is_empty() {
                return Err(WildcardError::Domain(DomainError::EmptyLabel));
            }
            let label = if raw.contains('*') {
                if raw != "*" {
                    return Err(WildcardError::PartialWildcard {
                        label: raw.to_string(),
                    });
                }
                wildcard_count += 1;
                Label::Any
            } else {
                let host = HostName::parse(raw)?;
                let text = host.as_str().to_string();
                if text.len() > MAX_LABEL_LEN {
                    return Err(WildcardError::Domain(DomainError::LabelTooLong {
                        label: text,
                    }));
                }
                Label::Literal(text)
            };
            if idx > 0 {
                canonical.push('.');
            }
            match &label {
                Label::Any => canonical.push('*'),
                Label::Literal(l) => canonical.push_str(l),
            }
            labels.push(label);
        }

        if labels.is_empty() {
            return Err(WildcardError::Empty);
        }
        Ok(WildcardPattern {
            labels,
            canonical,
            wildcard_count,
        })
    }

    /// True when this pattern contains no `*` at all (i.e. it is a plain exact-match domain).
    pub fn is_concrete(&self) -> bool {
        self.wildcard_count == 0
    }

    /// The canonical textual form of the pattern.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Number of `*` labels in the pattern.
    pub fn wildcard_count(&self) -> usize {
        self.wildcard_count
    }

    /// Matches a canonical host name against this pattern.
    pub fn matches(&self, host: &HostName) -> bool {
        let mut host_labels = host.labels();
        for label in &self.labels {
            let Some(candidate) = host_labels.next() else {
                return false;
            };
            match label {
                Label::Any => {}
                Label::Literal(expected) => {
                    if candidate != expected {
                        return false;
                    }
                }
            }
        }
        // The host must have exactly as many labels as the pattern.
        host_labels.next().is_none()
    }
}

impl fmt::Display for WildcardPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(s: &str) -> HostName {
        HostName::parse(s).unwrap()
    }

    #[test]
    fn single_label_wildcard() {
        let p = WildcardPattern::parse("api.*.example.com").unwrap();
        assert_eq!(p.wildcard_count(), 1);
        assert!(p.matches(&host("api.dev.example.com")));
        assert!(p.matches(&host("api.prod.example.com")));
        // `*` matches exactly one label.
        assert!(!p.matches(&host("api.example.com")));
        assert!(!p.matches(&host("api.a.b.example.com")));
        assert!(!p.matches(&host("www.dev.example.com")));
        // A wildcard is not a suffix match.
        assert!(!p.matches(&host("api.dev.example.com.evil.test")));
    }

    #[test]
    fn wildcard_is_case_and_idna_normalised() {
        let p = WildcardPattern::parse("API.*.Example.COM").unwrap();
        assert_eq!(p.as_str(), "api.*.example.com");
        assert!(p.matches(&host("api.DEV.example.com")));

        let u = WildcardPattern::parse("*.bücher.example").unwrap();
        assert_eq!(u.as_str(), "*.xn--bcher-kva.example");
        assert!(u.matches(&host("shop.bücher.example")));
    }

    #[test]
    fn partial_wildcard_rejected() {
        assert!(matches!(
            WildcardPattern::parse("a*b.example.com"),
            Err(WildcardError::PartialWildcard { .. })
        ));
        assert!(matches!(
            WildcardPattern::parse("**.example.com"),
            Err(WildcardError::PartialWildcard { .. })
        ));
    }

    #[test]
    fn concrete_pattern_detection() {
        assert!(WildcardPattern::parse("github.com").unwrap().is_concrete());
        assert!(!WildcardPattern::parse("*.github.com")
            .unwrap()
            .is_concrete());
    }

    #[test]
    fn multiple_wildcards() {
        let p = WildcardPattern::parse("*.api.*.example.com").unwrap();
        assert_eq!(p.wildcard_count(), 2);
        assert!(p.matches(&host("a.api.b.example.com")));
        assert!(!p.matches(&host("a.api.example.com")));
    }
}

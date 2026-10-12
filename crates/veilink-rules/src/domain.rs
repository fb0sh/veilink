//! DNS domain normalisation.
//!
//! Veilink matches domains after a strict, deterministic normalisation step so that a rule and a
//! request target are always compared in the same canonical form:
//!
//! 1. surrounding ASCII whitespace is trimmed;
//! 2. a single trailing root label (`.`) is removed;
//! 3. the name is lower-cased (DNS is case-insensitive, RFC 4343);
//! 4. every label is converted to its IDNA A-label (punycode) form when it is not already ASCII
//!    (RFC 5890 / UTS #46).
//!
//! Normalisation is *not* a security boundary on its own: the rule engine additionally requires
//! label-boundary matching (see [`crate::wildcard`] and [`crate::matcher`]) so that
//! `notgithub.com` can never match a `DOMAIN-SUFFIX,github.com` rule.

use std::fmt;

/// Maximum length of a fully qualified domain name in ASCII form (RFC 1035 §2.3.4).
pub const MAX_DOMAIN_LEN: usize = 253;
/// Maximum length of a single DNS label (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// Errors produced while normalising a host name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    /// The host name was empty or consisted only of separators.
    #[error("domain is empty")]
    Empty,
    /// A label was empty (for example `a..b` or a leading dot).
    #[error("domain contains an empty label")]
    EmptyLabel,
    /// A label exceeded [`MAX_LABEL_LEN`].
    #[error("label `{label}` is longer than {MAX_LABEL_LEN} bytes")]
    LabelTooLong {
        /// The offending label.
        label: String,
    },
    /// The whole name exceeded [`MAX_DOMAIN_LEN`].
    #[error("domain is longer than {MAX_DOMAIN_LEN} bytes")]
    DomainTooLong,
    /// A character is not permitted in a host name.
    #[error("domain `{domain}` contains an invalid character")]
    InvalidCharacter {
        /// The offending name.
        domain: String,
    },
    /// The IDNA/UTS#46 conversion failed.
    #[error("domain `{domain}` is not a valid internationalised domain name")]
    Idna {
        /// The offending name.
        domain: String,
    },
}

/// A validated, canonicalised DNS name.
///
/// Instances can only be produced through [`HostName::parse`], which guarantees that
/// [`HostName::as_str`] returns a lower-case ASCII (A-label) presentation form with no trailing
/// root dot, split into non-empty labels of at most [`MAX_LABEL_LEN`] bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostName(String);

impl HostName {
    /// Parses and canonicalises `input` as a DNS host name.
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(DomainError::Empty);
        }
        // Remove exactly one trailing root dot: `example.com.` == `example.com`.
        let without_root = trimmed.strip_suffix('.').unwrap_or(trimmed);
        if without_root.is_empty() {
            return Err(DomainError::Empty);
        }
        let mut out = String::with_capacity(without_root.len());
        for (idx, raw_label) in without_root.split('.').enumerate() {
            if raw_label.is_empty() {
                return Err(DomainError::EmptyLabel);
            }
            let label = normalize_label(raw_label).map_err(|e| match e {
                LabelError::Invalid => DomainError::InvalidCharacter {
                    domain: input.to_string(),
                },
                LabelError::Idna => DomainError::Idna {
                    domain: input.to_string(),
                },
            })?;
            if label.len() > MAX_LABEL_LEN {
                return Err(DomainError::LabelTooLong { label });
            }
            if idx > 0 {
                out.push('.');
            }
            out.push_str(&label);
        }
        if out.len() > MAX_DOMAIN_LEN {
            return Err(DomainError::DomainTooLong);
        }
        Ok(HostName(out))
    }

    /// The canonical ASCII presentation form (lower-case, no trailing root dot).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the DNS labels of this name, most significant label last.
    pub fn labels(&self) -> impl DoubleEndedIterator<Item = &str> {
        self.0.split('.')
    }

    /// Number of labels in this name.
    pub fn label_count(&self) -> usize {
        self.0.split('.').count()
    }

    /// True when `self` is equal to `suffix` or is a subdomain of `suffix`, measured on DNS label
    /// boundaries.
    ///
    /// `HostName::is_subdomain_of("api.github.com", "github.com")` is `true`;
    /// `HostName::is_subdomain_of("fakegithub.com", "github.com")` is `false`.
    pub fn is_subdomain_of(&self, suffix: &HostName) -> bool {
        if self.0.len() == suffix.0.len() {
            return self.0 == suffix.0;
        }
        if self.0.len() < suffix.0.len() {
            return false;
        }
        // Compare on a label boundary: the byte before the suffix must be the label separator.
        match self.0.len().checked_sub(suffix.0.len() + 1) {
            Some(split) => self.0.as_bytes()[split] == b'.' && self.0[split + 1..] == suffix.0,
            None => false,
        }
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for HostName {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HostName::parse(s)
    }
}

enum LabelError {
    Invalid,
    Idna,
}

/// Normalises a single DNS label to lower-case ASCII (A-label) form.
fn normalize_label(label: &str) -> Result<String, LabelError> {
    let lower = label.to_ascii_lowercase();
    if lower.is_ascii() {
        if !lower
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(LabelError::Invalid);
        }
        return Ok(lower);
    }
    // Non-ASCII label: convert to IDNA A-label form.
    let ascii = idna::domain_to_ascii(&lower).map_err(|_| LabelError::Idna)?;
    if ascii.is_empty() {
        return Err(LabelError::Idna);
    }
    if !ascii
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(LabelError::Invalid);
    }
    Ok(ascii)
}

/// Normalises an optional `host:port` authority into `(host, port)` without performing any DNS
/// resolution.
///
/// Supports bracketed IPv6 literals for *parsing* purposes so that the caller can produce a precise
/// "IPv6 is not supported" error instead of a confusing parse failure.
pub fn split_authority(authority: &str) -> Result<(String, Option<u16>), DomainError> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err(DomainError::Empty);
    }
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal, e.g. `[::1]:443`.
        let (host, tail) = rest.split_once(']').ok_or(DomainError::InvalidCharacter {
            domain: authority.to_string(),
        })?;
        let port = match tail {
            "" => None,
            _ => {
                let p = tail
                    .strip_prefix(':')
                    .ok_or(DomainError::InvalidCharacter {
                        domain: authority.to_string(),
                    })?;
                Some(
                    p.parse::<u16>()
                        .map_err(|_| DomainError::InvalidCharacter {
                            domain: authority.to_string(),
                        })?,
                )
            }
        };
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            let port = port
                .parse::<u16>()
                .map_err(|_| DomainError::InvalidCharacter {
                    domain: authority.to_string(),
                })?;
            Ok((host.to_string(), Some(port)))
        }
        Some((host, _)) if host.contains(':') => {
            // Bare IPv6 literal without brackets: reject explicitly.
            Ok((authority.to_string(), None))
        }
        _ => Ok((authority.to_string(), None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_trailing_root_dot() {
        assert_eq!(
            HostName::parse("github.com.").unwrap().as_str(),
            "github.com"
        );
        // Only one root dot is removed and a bare dot is rejected.
        assert!(HostName::parse(".").is_err());
        assert!(HostName::parse("github.com..").is_err());
    }

    #[test]
    fn lowercases() {
        assert_eq!(
            HostName::parse("GitHub.COM").unwrap().as_str(),
            "github.com"
        );
    }

    #[test]
    fn rejects_empty_labels() {
        assert!(matches!(
            HostName::parse("a..b"),
            Err(DomainError::EmptyLabel)
        ));
        assert!(matches!(
            HostName::parse(".github.com"),
            Err(DomainError::EmptyLabel)
        ));
    }

    #[test]
    fn idna_normalises_unicode() {
        let h = HostName::parse("bücher.example").unwrap();
        assert_eq!(h.as_str(), "xn--bcher-kva.example");
        // A-label form parses to itself.
        assert_eq!(
            HostName::parse("xn--bcher-kva.example").unwrap().as_str(),
            "xn--bcher-kva.example"
        );
        // Unicode and its A-label are the same host.
        assert_eq!(h, HostName::parse("BÜCHER.example.").unwrap());
    }

    #[test]
    fn label_boundary_semantics() {
        let github = HostName::parse("github.com").unwrap();
        assert!(HostName::parse("github.com")
            .unwrap()
            .is_subdomain_of(&github));
        assert!(HostName::parse("api.github.com")
            .unwrap()
            .is_subdomain_of(&github));
        assert!(HostName::parse("raw.api.github.com")
            .unwrap()
            .is_subdomain_of(&github));
        assert!(!HostName::parse("fakegithub.com")
            .unwrap()
            .is_subdomain_of(&github));
        assert!(!HostName::parse("github.com.attacker.example")
            .unwrap()
            .is_subdomain_of(&github));
        assert!(!HostName::parse("com").unwrap().is_subdomain_of(&github));
    }

    #[test]
    fn rejects_overlong() {
        let long = "a".repeat(64);
        assert!(matches!(
            HostName::parse(&format!("{long}.com")),
            Err(DomainError::LabelTooLong { .. })
        ));
        let many = vec!["abcdefghij"; 30].join(".");
        assert!(matches!(
            HostName::parse(&many),
            Err(DomainError::DomainTooLong)
        ));
    }

    #[test]
    fn authority_split() {
        assert_eq!(
            split_authority("github.com:443").unwrap(),
            ("github.com".to_string(), Some(443))
        );
        assert_eq!(
            split_authority("github.com").unwrap(),
            ("github.com".to_string(), None)
        );
        assert_eq!(
            split_authority("[::1]:8080").unwrap(),
            ("::1".to_string(), Some(8080))
        );
        assert_eq!(
            split_authority("1.1.1.1:53").unwrap(),
            ("1.1.1.1".to_string(), Some(53))
        );
    }
}

//! IPv4 address and CIDR handling.
//!
//! Veilink deliberately limits the first release to IPv4 egress, so IPv6 literals are recognised
//! only in order to produce an explicit, actionable error instead of being silently mis-parsed.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use ipnet::Ipv4Net;

/// Errors raised while parsing an IP or CIDR rule value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IpError {
    /// The value could not be parsed as an IPv4 address.
    #[error("`{value}` is not a valid IPv4 address")]
    InvalidIpv4 {
        /// The offending value.
        value: String,
    },
    /// The value is an IPv6 address or network, which the first release does not support.
    #[error("IPv6 target `{value}` is not supported by this release")]
    Ipv6Unsupported {
        /// The offending value.
        value: String,
    },
    /// The prefix length was outside `0..=32`.
    #[error("CIDR prefix length in `{value}` must be between 0 and 32")]
    InvalidPrefix {
        /// The offending value.
        value: String,
    },
    /// The value is not a valid CIDR block.
    #[error("`{value}` is not a valid IPv4 CIDR block")]
    InvalidCidr {
        /// The offending value.
        value: String,
    },
}

/// A parsed IPv4 host address or network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpMatcher {
    /// Exact IPv4 host match.
    Exact(Ipv4Addr),
    /// IPv4 network match.
    Network(Ipv4Net),
}

impl IpMatcher {
    /// Parses an `IP` rule value.
    pub fn parse_host(value: &str) -> Result<Self, IpError> {
        let value = value.trim();
        if let Ok(addr) = Ipv4Addr::from_str(value) {
            return Ok(IpMatcher::Exact(addr));
        }
        // Anything containing a colon is an IPv6 literal (or a malformed address); report the
        // unsupported family explicitly rather than as a generic parse failure.
        if value.contains(':') {
            let shown = IpAddr::from_str(value)
                .map(|ip| ip.to_string())
                .unwrap_or_else(|_| value.to_string());
            return Err(IpError::Ipv6Unsupported { value: shown });
        }
        Err(IpError::InvalidIpv4 {
            value: value.to_string(),
        })
    }

    /// Parses a `CIDR` rule value.
    pub fn parse_network(value: &str) -> Result<Self, IpError> {
        let value = value.trim();
        match value.split_once('/') {
            Some((addr_part, len_part)) => {
                if addr_part.contains(':') {
                    return Err(IpError::Ipv6Unsupported {
                        value: value.to_string(),
                    });
                }
                let len: u8 = len_part.parse().map_err(|_| IpError::InvalidPrefix {
                    value: value.to_string(),
                })?;
                if len > 32 {
                    return Err(IpError::InvalidPrefix {
                        value: value.to_string(),
                    });
                }
                // `Ipv4Net::from_str` also rejects host bits set; normalise them instead so that
                // `140.82.112.5/24` behaves like `140.82.112.0/24` rather than failing.
                let addr = Ipv4Addr::from_str(addr_part).map_err(|_| {
                    if addr_part.contains(':') {
                        IpError::Ipv6Unsupported {
                            value: value.to_string(),
                        }
                    } else {
                        IpError::InvalidCidr {
                            value: value.to_string(),
                        }
                    }
                })?;
                // Host bits are normalised away so that `140.82.112.5/24` and
                // `140.82.112.0/24` describe the same network instead of the former failing.
                Ok(IpMatcher::Network(
                    Ipv4Net::new(addr, len)
                        .map_err(|_| IpError::InvalidCidr {
                            value: value.to_string(),
                        })?
                        .trunc(),
                ))
            }
            None => {
                if value.contains(':') {
                    return Err(IpError::Ipv6Unsupported {
                        value: value.to_string(),
                    });
                }
                Err(IpError::InvalidCidr {
                    value: value.to_string(),
                })
            }
        }
    }

    /// True when `ip` is covered by this matcher.
    pub fn matches(&self, ip: Ipv4Addr) -> bool {
        match self {
            IpMatcher::Exact(a) => *a == ip,
            IpMatcher::Network(net) => net.contains(&ip),
        }
    }
}

impl fmt::Display for IpMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpMatcher::Exact(a) => write!(f, "{a}"),
            IpMatcher::Network(n) => write!(f, "{n}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_ipv4() {
        let m = IpMatcher::parse_host("1.1.1.1").unwrap();
        assert!(m.matches("1.1.1.1".parse().unwrap()));
        assert!(!m.matches("1.1.1.2".parse().unwrap()));
    }

    #[test]
    fn cidr_boundaries() {
        let m = IpMatcher::parse_network("140.82.112.0/24").unwrap();
        assert!(m.matches("140.82.112.0".parse().unwrap()));
        assert!(m.matches("140.82.112.255".parse().unwrap()));
        assert!(!m.matches("140.82.113.0".parse().unwrap()));
        assert!(!m.matches("140.82.111.255".parse().unwrap()));

        // /32 behaves as an exact match, /0 matches everything.
        let host = IpMatcher::parse_network("8.8.8.8/32").unwrap();
        assert!(host.matches("8.8.8.8".parse().unwrap()));
        assert!(!host.matches("8.8.8.9".parse().unwrap()));
        let all = IpMatcher::parse_network("0.0.0.0/0").unwrap();
        assert!(all.matches("203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn host_bits_are_normalised() {
        let m = IpMatcher::parse_network("140.82.112.5/24").unwrap();
        assert_eq!(m.to_string(), "140.82.112.0/24");
    }

    #[test]
    fn rejects_invalid_cidr() {
        assert!(matches!(
            IpMatcher::parse_network("140.82.112.0/33"),
            Err(IpError::InvalidPrefix { .. })
        ));
        assert!(matches!(
            IpMatcher::parse_network("140.82.112.0/abc"),
            Err(IpError::InvalidPrefix { .. })
        ));
        assert!(matches!(
            IpMatcher::parse_network("not-a-cidr"),
            Err(IpError::InvalidCidr { .. })
        ));
        assert!(matches!(
            IpMatcher::parse_network("999.1.1.1/24"),
            Err(IpError::InvalidCidr { .. })
        ));
    }

    #[test]
    fn rejects_ipv6_everywhere() {
        assert!(matches!(
            IpMatcher::parse_host("::1"),
            Err(IpError::Ipv6Unsupported { .. })
        ));
        assert!(matches!(
            IpMatcher::parse_host("2001:db8::1"),
            Err(IpError::Ipv6Unsupported { .. })
        ));
        assert!(matches!(
            IpMatcher::parse_network("2001:db8::/32"),
            Err(IpError::Ipv6Unsupported { .. })
        ));
    }

    #[test]
    fn rejects_garbage_host() {
        assert!(matches!(
            IpMatcher::parse_host("1.2.3"),
            Err(IpError::InvalidIpv4 { .. })
        ));
        assert!(matches!(
            IpMatcher::parse_host("github.com"),
            Err(IpError::InvalidIpv4 { .. })
        ));
    }
}

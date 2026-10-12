//! Route targets, authority parsing and Direct/Proxy route selection.

use std::net::Ipv4Addr;

use veilink_rules::{Decision, HostName, Target};

use crate::http::{Authority, HttpError, MAX_AUTHORITY_BYTES};

/// Errors raised while interpreting a request target or opening a route.
#[derive(Debug, thiserror::Error)]
pub enum RouteError {
    /// The authority was syntactically invalid.
    #[error("invalid target authority: {0}")]
    BadAuthority(String),
    /// IPv6 targets are not supported by this release.
    #[error("IPv6 target `{0}` is not supported by this release")]
    Ipv6Unsupported(String),
    /// The tunnel could not open a stream to the target.
    #[error("{tunnel} route failed to open a connection to {target}: {source}")]
    TunnelConnect {
        /// Tunnel name, for example `direct` or `vlp`.
        tunnel: &'static str,
        /// Target the connection was for.
        target: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A route matched the whitelist but no remote tunnel is available.
    #[error(
        "request for `{target}` matched the whitelist but no secure tunnel is available; \
         refusing to fall back to a direct connection"
    )]
    TunnelUnavailable {
        /// The target that could not be routed.
        target: String,
    },
}

impl From<RouteError> for HttpError {
    fn from(value: RouteError) -> Self {
        match value {
            RouteError::BadAuthority(m) => HttpError::BadAuthority(m),
            RouteError::Ipv6Unsupported(m) => HttpError::BadAuthority(m),
            RouteError::TunnelUnavailable { target } => HttpError::BadAuthority(target),
            RouteError::TunnelConnect { target, source, .. } => {
                HttpError::BadAuthority(format!("{target}: {source}"))
            }
        }
    }
}

/// Splits `host[:port]` without performing any DNS resolution.
///
/// Bracketed IPv6 literals are parsed so that the caller can reject them with a precise message
/// rather than treating them as a malformed host name.
pub fn split_host_port(input: &str, default_port: u16) -> Result<(String, u16), HttpError> {
    let input = input.trim();
    if input.is_empty() {
        return Err(HttpError::BadAuthority("host is empty".to_string()));
    }
    if input.len() > MAX_AUTHORITY_BYTES {
        return Err(HttpError::BadAuthority(format!(
            "host is longer than {MAX_AUTHORITY_BYTES} bytes"
        )));
    }
    if input.starts_with('[') {
        return Err(HttpError::BadAuthority(format!(
            "IPv6 target `{input}` is not supported by this release"
        )));
    }
    let (host, port) = match input.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            // A numeric suffix is only a port when the remainder is not itself an IPv6 literal;
            // `::1` would otherwise be read as host `::` with port `1`.
            if host.contains(':') {
                return Err(ipv6_error(input));
            }
            let port: u16 = port.parse().map_err(|_| {
                HttpError::BadAuthority(format!("`{port}` is not a valid port number"))
            })?;
            (host, port)
        }
        Some((host, _)) if host.contains(':') => return Err(ipv6_error(input)),
        _ => (input, default_port),
    };
    if host.is_empty() {
        return Err(HttpError::BadAuthority("host is empty".to_string()));
    }
    if port == 0 {
        return Err(HttpError::BadAuthority(
            "port 0 is not a valid destination port".to_string(),
        ));
    }
    if host.len() > MAX_AUTHORITY_BYTES {
        return Err(HttpError::BadAuthority("host is too long".to_string()));
    }
    if host
        .bytes()
        .any(|b| b.is_ascii_control() || b == b' ' || b == b'/' || b == b'\\')
    {
        return Err(HttpError::BadAuthority(
            "host contains characters that are not allowed in a host name".to_string(),
        ));
    }
    Ok((host.to_string(), port))
}

fn ipv6_error(input: &str) -> HttpError {
    HttpError::BadAuthority(format!(
        "IPv6 target `{input}` is not supported by this release"
    ))
}

/// A request destination, in both its original and canonical forms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTarget {
    /// The authority exactly as the client wrote it.
    pub authority: Authority,
    /// Canonical host name, for domain targets.
    pub normalized: Option<HostName>,
    /// The routing target used for whitelist evaluation.
    pub target: Target,
}

impl RouteTarget {
    /// Builds a route target from an authority.
    pub fn new(authority: Authority) -> Result<Self, RouteError> {
        let host = authority.host.trim();
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(RouteTarget {
                authority: Authority {
                    host: ip.to_string(),
                    port: authority.port,
                },
                normalized: None,
                target: Target::Ipv4(ip),
            });
        }
        if host.contains(':') {
            return Err(RouteError::Ipv6Unsupported(host.to_string()));
        }
        let normalized = HostName::parse(host)
            .map_err(|e| RouteError::BadAuthority(format!("`{host}`: {e}")))?;
        Ok(RouteTarget {
            authority: Authority {
                host: host.to_string(),
                port: authority.port,
            },
            normalized: Some(normalized.clone()),
            target: Target::Domain(normalized),
        })
    }

    /// The host string that should be sent to the remote server.
    ///
    /// Whitelisted domain names are forwarded *unresolved*: the canonical form is sent so the
    /// server resolves exactly the name that was matched, and the client never performs a DNS
    /// lookup for it.
    pub fn transmit_host(&self) -> &str {
        match &self.normalized {
            Some(name) => name.as_str(),
            None => &self.authority.host,
        }
    }
}

/// Applies a routing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteSelection {
    /// Connect from the local host, using the system resolver.
    Direct,
    /// Forward through the Veilink server, which resolves the name remotely.
    Proxy {
        /// Canonical form of the whitelist rule that matched.
        rule: String,
    },
}

impl RouteSelection {
    /// The short label used in logs.
    pub fn label(&self) -> &'static str {
        match self {
            RouteSelection::Direct => "DIRECT",
            RouteSelection::Proxy { .. } => "PROXY",
        }
    }

    /// Derives a selection from a rule engine decision.
    pub fn from_decision(decision: &Decision) -> Self {
        match decision {
            Decision::Proxy { rule, .. } => RouteSelection::Proxy { rule: rule.clone() },
            Decision::Direct => RouteSelection::Direct,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_host_and_port() {
        assert_eq!(
            split_host_port("example.com", 80).unwrap(),
            ("example.com".to_string(), 80)
        );
        assert_eq!(
            split_host_port("example.com:8080", 80).unwrap(),
            ("example.com".to_string(), 8080)
        );
        assert_eq!(
            split_host_port("1.2.3.4:443", 80).unwrap(),
            ("1.2.3.4".to_string(), 443)
        );
    }

    #[test]
    fn rejects_ipv6_and_garbage() {
        assert!(split_host_port("[::1]:443", 80).is_err());
        assert!(split_host_port("::1", 80).is_err());
        assert!(split_host_port("2001:db8::1", 80).is_err());
        assert!(split_host_port("", 80).is_err());
        assert!(split_host_port("host:0", 80).is_err());
        assert!(split_host_port("host:99999999", 80).is_err());
        assert!(split_host_port("bad host", 80).is_err());
        assert!(split_host_port("bad\nhost", 80).is_err());
        assert!(split_host_port("bad/host", 80).is_err());
    }

    #[test]
    fn classifies_domain_and_ip_literals() {
        let t = RouteTarget::new(Authority {
            host: "GitHub.com".into(),
            port: 443,
        })
        .unwrap();
        assert_eq!(t.normalized.as_ref().unwrap().as_str(), "github.com");
        assert_eq!(t.transmit_host(), "github.com");
        assert!(t.target.is_domain());

        let t = RouteTarget::new(Authority {
            host: "1.1.1.1".into(),
            port: 80,
        })
        .unwrap();
        assert!(t.normalized.is_none());
        assert_eq!(t.transmit_host(), "1.1.1.1");
        assert_eq!(t.target, Target::Ipv4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn rejects_ipv6_route_targets() {
        let err = RouteTarget::new(Authority {
            host: "::1".into(),
            port: 443,
        })
        .unwrap_err();
        assert!(matches!(err, RouteError::Ipv6Unsupported(_)));
    }

    #[test]
    fn selection_labels() {
        assert_eq!(RouteSelection::Direct.label(), "DIRECT");
        assert_eq!(
            RouteSelection::Proxy {
                rule: "DOMAIN,x".into()
            }
            .label(),
            "PROXY"
        );
    }
}

//! Outbound access control.
//!
//! A Veilink server is an authenticated relay, but authentication only proves *who* is asking — it
//! says nothing about *where* they may go. A compromised or simply curious client must not be able
//! to use the VPS as a pivot into its own loopback interface, its private network, or a cloud
//! metadata endpoint.
//!
//! The policy therefore denies, by default:
//!
//! * every IANA special-use IPv4 range, including loopback, RFC 1918 private space, link-local
//!   (`169.254.0.0/16`, which contains the cloud metadata address `169.254.169.254`), carrier-grade
//!   NAT, benchmarking and documentation ranges, multicast and reserved space;
//! * port 0.
//!
//! Two properties matter for correctness:
//!
//! 1. **The policy is applied to resolved addresses, not to the requested name.** Checking only the
//!    name would let an attacker point `evil.example` at `127.0.0.1`.
//! 2. **The connection is made to the address that was checked.** Veilink never re-resolves and
//!    never passes a name to the socket API, which closes the DNS-rebinding window between the
//!    check and the connect.
//!
//! [`EgressPolicy::allow_private_targets`] exists solely so that the integration tests can point
//! the server at a target on `127.0.0.1`. Even then, multicast, reserved and broadcast space stays
//! blocked.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

/// A denied destination.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyDeny {
    /// The destination port is not on the allow-list.
    #[error("port {0} is not in the server's allowed port list")]
    PortNotAllowed(u16),
    /// Port 0 is never a valid destination.
    #[error("port 0 is not a valid destination port")]
    InvalidPort,
    /// The destination address is in a special-use range.
    #[error("destination {address} is in the {range} range ({reason})")]
    SpecialUse {
        /// The denied address.
        address: Ipv4Addr,
        /// The range that matched, in CIDR form.
        range: Ipv4Net,
        /// Why the range is blocked.
        reason: &'static str,
    },
}

/// IANA special-use IPv4 ranges that are always denied.
const ALWAYS_DENIED: &[(&str, &str)] = &[
    ("0.0.0.0/8", "this network"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved for future use"),
    ("255.255.255.255/32", "limited broadcast"),
    ("192.0.0.0/24", "IETF protocol assignments"),
];

/// Ranges that are denied unless private targets are explicitly enabled for testing.
const PRIVATE_DENIED: &[(&str, &str)] = &[
    ("10.0.0.0/8", "RFC 1918 private network"),
    ("100.64.0.0/10", "carrier-grade NAT"),
    ("127.0.0.0/8", "loopback"),
    (
        "169.254.0.0/16",
        "link-local (includes cloud metadata endpoints)",
    ),
    ("172.16.0.0/12", "RFC 1918 private network"),
    ("192.0.2.0/24", "documentation TEST-NET-1"),
    ("192.88.99.0/24", "deprecated 6to4 relay anycast"),
    ("192.168.0.0/16", "RFC 1918 private network"),
    ("198.18.0.0/15", "benchmarking"),
    ("198.51.100.0/24", "documentation TEST-NET-2"),
    ("203.0.113.0/24", "documentation TEST-NET-3"),
];

/// The server's outbound access policy.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    /// When `true`, loopback and private ranges are permitted. Testing only.
    pub allow_private_targets: bool,
    /// Permitted destination ports. Empty means "all ports".
    pub allowed_ports: Vec<u16>,
}

impl EgressPolicy {
    /// Builds a policy.
    pub fn new(allow_private_targets: bool, allowed_ports: Vec<u16>) -> Self {
        EgressPolicy {
            allow_private_targets,
            allowed_ports,
        }
    }

    /// A policy that denies every special-use destination.
    pub fn strict() -> Self {
        EgressPolicy::new(false, Vec::new())
    }

    /// Checks a destination port.
    pub fn check_port(&self, port: u16) -> Result<(), PolicyDeny> {
        if port == 0 {
            return Err(PolicyDeny::InvalidPort);
        }
        if self.allowed_ports.is_empty() || self.allowed_ports.contains(&port) {
            return Ok(());
        }
        Err(PolicyDeny::PortNotAllowed(port))
    }

    /// Checks a resolved destination address.
    pub fn check_address(&self, address: Ipv4Addr) -> Result<(), PolicyDeny> {
        for (range, reason) in ALWAYS_DENIED {
            if let Some(net) = parse_range(range) {
                if net.contains(&address) {
                    return Err(PolicyDeny::SpecialUse {
                        address,
                        range: net,
                        reason,
                    });
                }
            }
        }
        if self.allow_private_targets {
            return Ok(());
        }
        for (range, reason) in PRIVATE_DENIED {
            if let Some(net) = parse_range(range) {
                if net.contains(&address) {
                    return Err(PolicyDeny::SpecialUse {
                        address,
                        range: net,
                        reason,
                    });
                }
            }
        }
        Ok(())
    }

    /// Checks a port and every resolved address.
    ///
    /// Returns the permitted addresses in the order given, or the first denial. A name that
    /// resolves to a mixture of public and private addresses is refused outright rather than
    /// silently filtered: that pattern is a strong signal of a rebinding attempt, and quietly
    /// connecting to the public half would reward it.
    pub fn filter_addresses(
        &self,
        port: u16,
        addresses: &[Ipv4Addr],
    ) -> Result<Vec<Ipv4Addr>, PolicyDeny> {
        self.check_port(port)?;
        for address in addresses {
            self.check_address(*address)?;
        }
        Ok(addresses.to_vec())
    }
}

impl Default for EgressPolicy {
    fn default() -> Self {
        EgressPolicy::strict()
    }
}

fn parse_range(text: &str) -> Option<Ipv4Net> {
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn strict_policy_denies_special_use_ranges() {
        let policy = EgressPolicy::strict();
        let denied = [
            "127.0.0.1",
            "127.255.255.254",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "169.254.0.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "192.88.99.1",
        ];
        for address in denied {
            assert!(
                policy.check_address(ip(address)).is_err(),
                "{address} should have been denied"
            );
        }
    }

    #[test]
    fn strict_policy_allows_public_addresses() {
        let policy = EgressPolicy::strict();
        for address in ["1.1.1.1", "8.8.8.8", "140.82.112.4", "20.205.243.166"] {
            assert!(
                policy.check_address(ip(address)).is_ok(),
                "{address} should have been allowed"
            );
        }
    }

    #[test]
    fn private_targets_can_be_enabled_for_testing_but_never_multicast() {
        let policy = EgressPolicy::new(true, Vec::new());
        assert!(policy.check_address(ip("127.0.0.1")).is_ok());
        assert!(policy.check_address(ip("10.1.2.3")).is_ok());
        assert!(policy.check_address(ip("192.168.0.5")).is_ok());
        // Hard-blocked regardless.
        assert!(policy.check_address(ip("224.0.0.1")).is_err());
        assert!(policy.check_address(ip("255.255.255.255")).is_err());
        assert!(policy.check_address(ip("0.0.0.0")).is_err());
    }

    #[test]
    fn port_allow_list() {
        let policy = EgressPolicy::new(false, vec![80, 443]);
        assert!(policy.check_port(80).is_ok());
        assert!(policy.check_port(443).is_ok());
        assert_eq!(policy.check_port(22), Err(PolicyDeny::PortNotAllowed(22)));
        assert_eq!(policy.check_port(0), Err(PolicyDeny::InvalidPort));

        let open = EgressPolicy::strict();
        assert!(open.check_port(1).is_ok());
        assert!(open.check_port(65535).is_ok());
    }

    #[test]
    fn mixed_resolution_is_refused_entirely() {
        let policy = EgressPolicy::strict();
        let addresses = [ip("140.82.112.4"), ip("127.0.0.1")];
        let denied = policy.filter_addresses(443, &addresses);
        assert!(
            denied.is_err(),
            "a mixed public/private answer must be refused"
        );
    }

    #[test]
    fn deny_message_names_the_range_and_reason() {
        let policy = EgressPolicy::strict();
        let err = policy.check_address(ip("169.254.169.254")).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("169.254.0.0/16"), "{text}");
        assert!(text.contains("metadata"), "{text}");
    }
}

//! Remote DNS resolution for the Veilink server.
//!
//! The server performs the lookup for every whitelisted destination, which is what keeps the
//! client's resolver from learning the target names. The resolver is deliberately IPv4-only: the
//! first release has no IPv6 egress, so resolving AAAA records would only create a policy hole.
//!
//! Behaviour:
//!
//! * A-record queries only, with a bounded TTL cache.
//! * Per-query timeout and a small number of attempts.
//! * Names are normalised (lower-case, IDNA A-labels) before lookup so that the cache key matches
//!   what the client matched against the whitelist.
//! * Negative results are not cached, so a transient failure does not blackhole a name.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig,
    ResolverOpts,
};
use hickory_resolver::TokioAsyncResolver;
use tracing::{debug, warn};
use veilink_config::DnsConfig;

/// Errors raised while resolving a name.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The name is not a valid host name.
    #[error("`{0}` is not a valid host name")]
    InvalidName(String),
    /// The resolver returned no IPv4 address.
    #[error("no IPv4 address found for `{0}`")]
    NoAddress(String),
    /// Every attempt timed out or failed.
    #[error("DNS lookup for `{name}` failed after {attempts} attempt(s): {reason}")]
    Lookup {
        /// The name that failed.
        name: String,
        /// Number of attempts made.
        attempts: usize,
        /// Last error reported by the resolver.
        reason: String,
    },
}

/// A cached resolution result.
#[derive(Debug, Clone)]
struct CacheEntry {
    addresses: Vec<Ipv4Addr>,
    expires_at: Instant,
    last_used: u64,
}

/// An IPv4-only resolver with a bounded TTL cache.
pub struct Resolver {
    inner: TokioAsyncResolver,
    timeout: Duration,
    attempts: usize,
    cache_size: usize,
    cache: Mutex<HashMap<String, CacheEntry>>,
    clock: AtomicU64,
    lookups: AtomicU64,
    hits: AtomicU64,
    failures: AtomicU64,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("timeout", &self.timeout)
            .field("attempts", &self.attempts)
            .field("cache_size", &self.cache_size)
            .finish_non_exhaustive()
    }
}

impl Resolver {
    /// Builds a resolver from configuration.
    pub fn new(config: &DnsConfig) -> Result<Self, ResolveError> {
        let mut opts = ResolverOpts::default();
        // The explicit cache below is the only cache, so behaviour stays observable and testable.
        opts.cache_size = 0;
        opts.timeout = Duration::from_millis(config.timeout_ms.max(1));
        opts.attempts = config.attempts.max(1);
        opts.ip_strategy = LookupIpStrategy::Ipv4Only;
        opts.validate = true;

        let inner = if config.servers.is_empty() {
            TokioAsyncResolver::tokio_from_system_conf().map_err(|e| ResolveError::Lookup {
                name: "<system resolver>".to_string(),
                attempts: 1,
                reason: e.to_string(),
            })?
        } else {
            let mut group = NameServerConfigGroup::new();
            for server in &config.servers {
                let (ip, port) = split_server(server)?;
                group.push(NameServerConfig::new(
                    std::net::SocketAddr::new(ip, port),
                    Protocol::Udp,
                ));
            }
            let resolver_config = ResolverConfig::from_parts(None, vec![], group);
            TokioAsyncResolver::tokio(resolver_config, opts.clone())
        };

        Ok(Resolver {
            inner,
            timeout: Duration::from_millis(config.timeout_ms.max(1)),
            attempts: config.attempts.max(1),
            cache_size: config.cache_size.max(1),
            cache: Mutex::new(HashMap::new()),
            clock: AtomicU64::new(0),
            lookups: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        })
    }

    /// Number of lookups that reached the network.
    pub fn lookups(&self) -> u64 {
        self.lookups.load(Ordering::Relaxed)
    }

    /// Number of cache hits.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Number of failed lookups.
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Number of entries currently cached.
    pub fn cache_len(&self) -> usize {
        self.cache.lock().map(|c| c.len()).unwrap_or(0)
    }

    /// Resolves `host` to one or more IPv4 addresses.
    pub async fn resolve_ipv4(&self, host: &str) -> Result<Vec<Ipv4Addr>, ResolveError> {
        // An IPv4 literal needs no lookup at all.
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(vec![ip]);
        }
        let name = veilink_rules::HostName::parse(host)
            .map_err(|_| ResolveError::InvalidName(host.to_string()))?
            .as_str()
            .to_string();

        if let Some(addresses) = self.cache_get(&name) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            debug!(cached = true, "resolved host from cache");
            return Ok(addresses);
        }

        let mut last_error = String::new();
        for attempt in 0..self.attempts {
            self.lookups.fetch_add(1, Ordering::Relaxed);
            let lookup = self.inner.ipv4_lookup(name.clone());
            match tokio::time::timeout(self.timeout, lookup).await {
                Err(_) => {
                    last_error = format!("timed out after {}ms", self.timeout.as_millis());
                }
                Ok(Err(e)) => {
                    last_error = e.to_string();
                }
                Ok(Ok(lookup)) => {
                    let mut addresses: Vec<Ipv4Addr> = Vec::new();
                    for record in lookup.iter() {
                        let ip = record.0;
                        if !addresses.contains(&ip) {
                            addresses.push(ip);
                        }
                    }
                    // Honour the smallest TTL in the answer; a shorter-lived record must not be
                    // kept alive by a longer-lived companion.
                    let mut ttl: Option<Duration> = None;
                    for record in lookup.as_lookup().records() {
                        let candidate = Duration::from_secs(u64::from(record.ttl()));
                        ttl = Some(match ttl {
                            Some(current) => current.min(candidate),
                            None => candidate,
                        });
                    }
                    if addresses.is_empty() {
                        last_error = "response contained no A records".to_string();
                    } else {
                        // Cap the cache lifetime so that a very long TTL cannot pin a stale
                        // address, and floor it so that a zero TTL does not defeat the cache.
                        let ttl = ttl.unwrap_or(Duration::from_secs(60));
                        let ttl = ttl.clamp(Duration::from_secs(5), Duration::from_secs(3600));
                        self.cache_put(name.clone(), addresses.clone(), ttl);
                        return Ok(addresses);
                    }
                }
            }
            if attempt + 1 < self.attempts {
                debug!(attempt = attempt + 1, "retrying DNS lookup");
            }
        }

        self.failures.fetch_add(1, Ordering::Relaxed);
        warn!(error = %last_error, "DNS lookup failed");
        Err(ResolveError::Lookup {
            name,
            attempts: self.attempts,
            reason: last_error,
        })
    }

    fn cache_get(&self, name: &str) -> Option<Vec<Ipv4Addr>> {
        let mut cache = self.cache.lock().ok()?;
        let now = Instant::now();
        let entry = cache.get(name)?;
        if entry.expires_at <= now {
            cache.remove(name);
            return None;
        }
        let tick = self.clock.fetch_add(1, Ordering::Relaxed);
        let addresses = entry.addresses.clone();
        if let Some(entry) = cache.get_mut(name) {
            entry.last_used = tick;
        }
        Some(addresses)
    }

    fn cache_put(&self, name: String, addresses: Vec<Ipv4Addr>, ttl: Duration) {
        let Ok(mut cache) = self.cache.lock() else {
            return;
        };
        // Drop expired entries first so that the size bound reflects live data.
        let now = Instant::now();
        cache.retain(|_, entry| entry.expires_at > now);
        if cache.len() >= self.cache_size && !cache.contains_key(&name) {
            // Evict the least recently used entry.
            if let Some(victim) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            {
                cache.remove(&victim);
            }
        }
        let tick = self.clock.fetch_add(1, Ordering::Relaxed);
        cache.insert(
            name,
            CacheEntry {
                addresses,
                expires_at: now + ttl,
                last_used: tick,
            },
        );
    }

    /// Clears the cache. Used by tests.
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.clear();
        }
    }
}

/// Parses `IP` or `IP:PORT` from a configured name server entry.
fn split_server(entry: &str) -> Result<(std::net::IpAddr, u16), ResolveError> {
    let entry = entry.trim();
    let (ip_text, port) = match entry.rsplit_once(':') {
        Some((ip, port)) if !ip.contains(':') => (ip, port.parse().unwrap_or(53)),
        _ => (entry, 53),
    };
    let ip: std::net::IpAddr = ip_text.parse().map_err(|_| ResolveError::Lookup {
        name: entry.to_string(),
        attempts: 0,
        reason: "configured name server is not a valid IP address".to_string(),
    })?;
    Ok((ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_addresses_skip_the_resolver() {
        let resolver = Resolver::new(&DnsConfig {
            servers: vec!["127.0.0.1:53".to_string()],
            ..DnsConfig::default()
        })
        .unwrap();
        let addrs = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(resolver.resolve_ipv4("1.1.1.1"))
            .unwrap();
        assert_eq!(addrs, vec![Ipv4Addr::new(1, 1, 1, 1)]);
        assert_eq!(resolver.lookups(), 0);
    }

    #[test]
    fn invalid_names_are_rejected_without_a_query() {
        let resolver = Resolver::new(&DnsConfig {
            servers: vec!["127.0.0.1:53".to_string()],
            ..DnsConfig::default()
        })
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for bad in ["", "a..b", "::1"] {
            let err = runtime.block_on(resolver.resolve_ipv4(bad)).unwrap_err();
            assert!(
                matches!(
                    err,
                    ResolveError::InvalidName(_) | ResolveError::NoAddress(_)
                ),
                "{bad} produced {err}"
            );
        }
        assert_eq!(resolver.lookups(), 0);
    }

    #[test]
    fn cache_is_bounded_and_expires() {
        let resolver = Resolver::new(&DnsConfig {
            servers: vec!["127.0.0.1:53".to_string()],
            cache_size: 2,
            ..DnsConfig::default()
        })
        .unwrap();
        resolver.cache_put(
            "a.test".into(),
            vec![Ipv4Addr::new(1, 1, 1, 1)],
            Duration::from_secs(60),
        );
        resolver.cache_put(
            "b.test".into(),
            vec![Ipv4Addr::new(1, 1, 1, 2)],
            Duration::from_secs(60),
        );
        resolver.cache_put(
            "c.test".into(),
            vec![Ipv4Addr::new(1, 1, 1, 3)],
            Duration::from_secs(60),
        );
        assert_eq!(resolver.cache_len(), 2);
        assert!(
            resolver.cache_get("a.test").is_none(),
            "oldest entry was not evicted"
        );

        resolver.cache_put(
            "d.test".into(),
            vec![Ipv4Addr::new(1, 1, 1, 4)],
            Duration::from_secs(0),
        );
        // A zero TTL is floored by `resolve_ipv4`, but a directly inserted zero-TTL entry must
        // still be treated as already expired.
        assert!(resolver.cache_get("d.test").is_none());
    }

    #[test]
    fn server_entry_parsing() {
        assert_eq!(
            split_server("1.1.1.1").unwrap(),
            (std::net::IpAddr::from([1, 1, 1, 1]), 53)
        );
        assert_eq!(
            split_server("9.9.9.9:5353").unwrap(),
            (std::net::IpAddr::from([9, 9, 9, 9]), 5353)
        );
        assert!(split_server("nonsense").is_err());
    }

    #[test]
    fn resolver_builds_from_system_config() {
        // Must not panic on a machine whose /etc/resolv.conf is unusual.
        assert!(Resolver::new(&DnsConfig::default()).is_ok());
    }
}

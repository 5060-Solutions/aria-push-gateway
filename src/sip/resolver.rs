//! DNS SRV resolver for SIP upstream discovery.
//!
//! Resolves `_sip._udp.<domain>` (and TCP/TLS variants) to an ordered list of
//! server addresses, with priority/weight-based ordering and TTL-aware caching.
//! Falls back to A/AAAA record lookup when no SRV records exist.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::rdata::SRV;
use hickory_resolver::TokioAsyncResolver;
use tokio::sync::RwLock;

/// A resolved SIP server endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedServer {
    pub addr: SocketAddr,
    pub priority: u16,
    pub weight: u16,
}

/// The full ordered target list of a lookup and how long it may be used.
#[derive(Debug, Clone)]
pub struct Resolution {
    pub servers: Vec<ResolvedServer>,
    pub ttl: Duration,
}

/// Order targets per RFC 2782: ascending priority, and within one priority a
/// weighted random order (each pick is drawn in proportion to the remaining
/// weights; weight 0 targets come after the weighted ones, as the RFC asks
/// for them to be unlikely). `rand` yields uniform values in `[0, 1)`.
pub fn order_targets(
    mut servers: Vec<ResolvedServer>,
    mut rand: impl FnMut() -> f64,
) -> Vec<ResolvedServer> {
    servers.sort_by_key(|s| s.priority);
    let mut ordered = Vec::with_capacity(servers.len());
    while !servers.is_empty() {
        let priority = servers[0].priority;
        let n = servers
            .iter()
            .take_while(|s| s.priority == priority)
            .count();
        let mut group: Vec<ResolvedServer> = servers.drain(..n).collect();
        // Zero weights last, so they are only chosen when nothing else is.
        group.sort_by_key(|s| s.weight == 0);
        while !group.is_empty() {
            let total: u32 = group.iter().map(|s| u32::from(s.weight)).sum();
            let idx = if total == 0 {
                0
            } else {
                let pick = (rand().clamp(0.0, 0.999_999_9) * f64::from(total)) as u32;
                let mut acc = 0;
                group
                    .iter()
                    .position(|s| {
                        acc += u32::from(s.weight);
                        pick < acc
                    })
                    .unwrap_or(0)
            };
            ordered.push(group.remove(idx));
        }
    }
    ordered
}

/// Cached SRV resolution result.
struct CachedResolution {
    servers: Vec<ResolvedServer>,
    resolved_at: Instant,
    ttl: Duration,
}

/// DNS SRV resolver with TTL-aware caching.
pub struct SrvResolver {
    resolver: TokioAsyncResolver,
    cache: RwLock<std::collections::HashMap<String, CachedResolution>>,
}

impl SrvResolver {
    /// Create a new SRV resolver using system DNS configuration.
    pub fn new() -> anyhow::Result<Self> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Ok(Self {
            resolver,
            cache: RwLock::new(std::collections::HashMap::new()),
        })
    }

    /// Resolve a SIP domain to an ordered list of server addresses.
    ///
    /// Queries `_sip._<transport>.<domain>` for SRV records. Falls back to
    /// A/AAAA resolution on the domain directly if no SRV records are found.
    pub async fn resolve(
        &self,
        domain: &str,
        port: u16,
        transport: &str,
    ) -> anyhow::Result<Resolution> {
        // An IP literal names the server directly; there is nothing to look up.
        if let Ok(ip) = domain.parse::<std::net::IpAddr>() {
            return Ok(Resolution {
                servers: vec![ResolvedServer {
                    addr: SocketAddr::new(ip, port),
                    priority: 0,
                    weight: 0,
                }],
                ttl: Duration::from_secs(300),
            });
        }

        let srv_name = srv_service_name(domain, transport);

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&srv_name) {
                if let Some(left) = entry.ttl.checked_sub(entry.resolved_at.elapsed()) {
                    tracing::debug!(domain = %domain, "Using cached SRV resolution ({} servers)", entry.servers.len());
                    return Ok(Resolution {
                        servers: entry.servers.clone(),
                        ttl: left,
                    });
                }
            }
        }

        // Try SRV lookup
        match self.resolve_srv(&srv_name).await {
            Ok(found) if !found.servers.is_empty() => {
                tracing::info!(
                    domain = %domain,
                    srv = %srv_name,
                    count = found.servers.len(),
                    "SRV resolution successful"
                );
                return Ok(found);
            }
            Ok(_) => {
                tracing::debug!(domain = %domain, "No SRV records found, falling back to A record");
            }
            Err(e) => {
                tracing::debug!(domain = %domain, "SRV lookup failed ({}), falling back to A record", e);
            }
        }

        // Fallback to A/AAAA record
        self.resolve_a_record(domain, port).await
    }

    /// Resolve SRV records and return every target (every address of every
    /// SRV host), ordered by priority then weighted at random.
    async fn resolve_srv(&self, srv_name: &str) -> anyhow::Result<Resolution> {
        let lookup = self.resolver.srv_lookup(srv_name).await?;

        let mut srv_records: Vec<&SRV> = lookup.iter().collect();

        // Check for "." target which means "service not available"
        if srv_records.len() == 1 && srv_records[0].target().to_string() == "." {
            return Ok(Resolution {
                servers: vec![],
                ttl: Duration::ZERO,
            });
        }
        // Honour the SRV records' own TTL as well as the addresses'.
        let mut min_ttl = lookup
            .as_lookup()
            .valid_until()
            .duration_since(Instant::now())
            .as_secs()
            .clamp(30, 300) as u32;
        srv_records.sort_by_key(|r| r.priority());

        let mut servers = Vec::new();

        for record in &srv_records {
            let target = record.target().to_string();
            let target = target.trim_end_matches('.');
            let port = record.port();

            // Resolve the SRV target hostname to IP
            match self.resolver.lookup_ip(target).await {
                Ok(ips) => {
                    for ip in ips.iter() {
                        servers.push(ResolvedServer {
                            addr: SocketAddr::new(ip, port),
                            priority: record.priority(),
                            weight: record.weight(),
                        });
                    }
                    // Track minimum TTL from the A/AAAA records
                    let valid_until = ips.valid_until();
                    let ttl_secs = valid_until.duration_since(Instant::now()).as_secs() as u32;
                    min_ttl = min_ttl.min(ttl_secs.max(30));
                }
                Err(e) => {
                    tracing::warn!(target = %target, "Failed to resolve SRV target: {}", e);
                }
            }
        }

        let servers = order_targets(servers, rand::random::<f64>);
        let ttl = Duration::from_secs(u64::from(min_ttl.max(30)));
        if !servers.is_empty() {
            let mut cache = self.cache.write().await;
            cache.insert(
                srv_name.to_string(),
                CachedResolution {
                    servers: servers.clone(),
                    resolved_at: Instant::now(),
                    ttl,
                },
            );
        }

        Ok(Resolution { servers, ttl })
    }

    /// Fallback: resolve domain as A/AAAA record with the given port.
    async fn resolve_a_record(&self, domain: &str, port: u16) -> anyhow::Result<Resolution> {
        let ips = self.resolver.lookup_ip(domain).await?;

        let mut servers = Vec::new();
        for ip in ips.iter() {
            servers.push(ResolvedServer {
                addr: SocketAddr::new(ip, port),
                priority: 0,
                weight: 0,
            });
        }

        if servers.is_empty() {
            anyhow::bail!("No A/AAAA records found for {}", domain);
        }

        // Cache the A record result too
        let ttl = {
            let valid_until = ips.valid_until();
            let ttl_secs = valid_until.duration_since(Instant::now()).as_secs().max(30);
            Duration::from_secs(ttl_secs)
        };

        let srv_name = format!("_a_fallback.{}", domain);
        let mut cache = self.cache.write().await;
        cache.insert(
            srv_name,
            CachedResolution {
                servers: servers.clone(),
                resolved_at: Instant::now(),
                ttl,
            },
        );

        tracing::info!(domain = %domain, count = servers.len(), "A record fallback resolution");
        Ok(Resolution { servers, ttl })
    }
}

/// Build the SRV service name for SIP.
fn srv_service_name(domain: &str, transport: &str) -> String {
    let proto = match transport.to_lowercase().as_str() {
        "tcp" => "tcp",
        "tls" => "tls",
        _ => "udp",
    };
    format!("_sip._{}.{}", proto, domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ip_literals_resolve_without_dns() {
        let resolver = SrvResolver::new().unwrap();
        for (host, expected) in [("127.0.0.1", "127.0.0.1:5070"), ("::1", "[::1]:5070")] {
            let servers = tokio::time::timeout(
                Duration::from_millis(100),
                resolver.resolve(host, 5070, "udp"),
            )
            .await
            .expect("an IP literal must not wait on DNS")
            .unwrap();
            assert_eq!(servers.servers.len(), 1);
            assert_eq!(servers.servers[0].addr.to_string(), expected);
        }
    }

    fn srv(addr: &str, priority: u16, weight: u16) -> ResolvedServer {
        ResolvedServer {
            addr: addr.parse().unwrap(),
            priority,
            weight,
        }
    }

    fn addrs(v: &[ResolvedServer]) -> Vec<String> {
        v.iter().map(|s| s.addr.to_string()).collect()
    }

    #[test]
    fn targets_are_ordered_by_priority_first() {
        let list = vec![
            srv("10.0.0.3:5060", 20, 100),
            srv("10.0.0.1:5060", 10, 1),
            srv("10.0.0.2:5060", 10, 1),
        ];
        let out = order_targets(list, || 0.0);
        assert_eq!(out[2].addr.to_string(), "10.0.0.3:5060");
        assert_eq!(out[0].priority, 10);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn weights_pick_in_proportion_and_zero_weights_come_last() {
        let list = || {
            vec![
                srv("10.0.0.1:5060", 10, 0),
                srv("10.0.0.2:5060", 10, 30),
                srv("10.0.0.3:5060", 10, 70),
            ]
        };
        // Pick below 30/100 chooses the first weighted target, above it the second.
        let low = order_targets(list(), || 0.1);
        assert_eq!(
            addrs(&low),
            ["10.0.0.2:5060", "10.0.0.3:5060", "10.0.0.1:5060"]
        );
        let high = order_targets(list(), || 0.5);
        assert_eq!(
            addrs(&high),
            ["10.0.0.3:5060", "10.0.0.2:5060", "10.0.0.1:5060"]
        );
    }

    #[test]
    fn weighted_order_follows_the_weights_statistically() {
        let mut first_heavy = 0;
        let mut seed = 0u32;
        for _ in 0..1000 {
            let out = order_targets(
                vec![srv("10.0.0.1:5060", 1, 90), srv("10.0.0.2:5060", 1, 10)],
                || {
                    seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    f64::from(seed >> 8) / f64::from(1u32 << 24)
                },
            );
            if out[0].addr.to_string() == "10.0.0.1:5060" {
                first_heavy += 1;
            }
        }
        assert!((850..950).contains(&first_heavy), "{first_heavy}");
    }
}

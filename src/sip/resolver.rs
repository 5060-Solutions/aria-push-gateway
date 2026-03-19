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
#[derive(Debug, Clone)]
pub struct ResolvedServer {
    pub addr: SocketAddr,
    pub priority: u16,
    pub weight: u16,
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
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
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
    ) -> anyhow::Result<Vec<ResolvedServer>> {
        let srv_name = srv_service_name(domain, transport);

        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&srv_name) {
                if entry.resolved_at.elapsed() < entry.ttl {
                    tracing::debug!(domain = %domain, "Using cached SRV resolution ({} servers)", entry.servers.len());
                    return Ok(entry.servers.clone());
                }
            }
        }

        // Try SRV lookup
        match self.resolve_srv(&srv_name, domain, port).await {
            Ok(servers) if !servers.is_empty() => {
                tracing::info!(
                    domain = %domain,
                    srv = %srv_name,
                    count = servers.len(),
                    "SRV resolution successful"
                );
                return Ok(servers);
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

    /// Resolve SRV records and return servers ordered by priority then weight.
    async fn resolve_srv(
        &self,
        srv_name: &str,
        _domain: &str,
        _default_port: u16,
    ) -> anyhow::Result<Vec<ResolvedServer>> {
        let lookup = self.resolver.srv_lookup(srv_name).await?;

        let mut srv_records: Vec<&SRV> = lookup.iter().collect();

        // Check for "." target which means "service not available"
        if srv_records.len() == 1 && srv_records[0].target().to_string() == "." {
            return Ok(vec![]);
        }

        // Sort by priority (ascending), then by weight (descending) within same priority
        srv_records.sort_by(|a, b| {
            a.priority()
                .cmp(&b.priority())
                .then_with(|| b.weight().cmp(&a.weight()))
        });

        let mut servers = Vec::new();
        let mut min_ttl = 300u32; // default 5 min

        for record in &srv_records {
            let target = record.target().to_string();
            let target = target.trim_end_matches('.');
            let port = record.port();

            // Resolve the SRV target hostname to IP
            match self.resolver.lookup_ip(target).await {
                Ok(ips) => {
                    if let Some(ip) = ips.iter().next() {
                        servers.push(ResolvedServer {
                            addr: SocketAddr::new(ip, port),
                            priority: record.priority(),
                            weight: record.weight(),
                        });
                    }
                    // Track minimum TTL from the A/AAAA records
                    let valid_until = ips.valid_until();
                    let ttl_secs = valid_until
                        .duration_since(Instant::now())
                        .as_secs() as u32;
                    min_ttl = min_ttl.min(ttl_secs.max(30));
                }
                Err(e) => {
                    tracing::warn!(target = %target, "Failed to resolve SRV target: {}", e);
                }
            }
        }

        // Cache the result
        if !servers.is_empty() {
            let ttl = Duration::from_secs(min_ttl.max(30) as u64);
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

        Ok(servers)
    }

    /// Fallback: resolve domain as A/AAAA record with the given port.
    async fn resolve_a_record(
        &self,
        domain: &str,
        port: u16,
    ) -> anyhow::Result<Vec<ResolvedServer>> {
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
            let ttl_secs = valid_until
                .duration_since(Instant::now())
                .as_secs()
                .max(30);
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
        Ok(servers)
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

//! DNS SRV resolver for SIP upstream discovery.
//!
//! Resolves `_sips._tcp.<domain>`, `_sip._tcp.<domain>` or `_sip._udp.<domain>`
//! (or walks all three for `auto`, never stepping down from a published TLS
//! service) to an ordered list of server addresses, with priority/weight-based
//! ordering and TTL-aware caching. Falls back to A/AAAA record lookup when no
//! SRV records exist.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::rdata::SRV;
use hickory_resolver::TokioAsyncResolver;
use tokio::sync::RwLock;

use super::transport::Transport;

/// A resolved SIP server endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedServer {
    pub addr: SocketAddr,
    pub priority: u16,
    pub weight: u16,
    /// The SRV target (or the domain itself for an A/AAAA answer): what a
    /// TLS certificate is checked against (see
    /// [`super::transport::tls_server_name`]).
    pub host: String,
}

/// The full ordered target list of a lookup and how long it may be used.
#[derive(Debug, Clone)]
pub struct Resolution {
    pub servers: Vec<ResolvedServer>,
    pub ttl: Duration,
    /// The transport every server in the list is reached over.
    pub transport: Transport,
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

/// The transport a registration asks for: one transport, or `auto`, which
/// walks `_sips._tcp`, `_sip._tcp`, `_sip._udp` (RFC 3263 §4.1) and uses the
/// first one the domain publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Wanted {
    One(Transport),
    Auto,
}

impl Wanted {
    /// From a configured transport name (`udp`, `tcp`, `tls`, `auto`).
    /// Anything unknown is UDP, as it always was.
    pub fn parse(s: &str) -> Self {
        if s.eq_ignore_ascii_case("auto") {
            Self::Auto
        } else {
            Self::One(Transport::parse(s).unwrap_or(Transport::Udp))
        }
    }

    /// The SRV names to ask, in order, with the transport each is for.
    pub fn srv_names(self, domain: &str) -> Vec<(String, Transport)> {
        let tls = (format!("_sips._tcp.{domain}"), Transport::Tls);
        let tcp = (format!("_sip._tcp.{domain}"), Transport::Tcp);
        let udp = (format!("_sip._udp.{domain}"), Transport::Udp);
        match self {
            Self::One(Transport::Tls) => vec![tls],
            Self::One(Transport::Tcp) => vec![tcp],
            Self::One(Transport::Udp) => vec![udp],
            Self::Auto => vec![tls, tcp, udp],
        }
    }

    /// The transport of an A/AAAA fallback (RFC 3263 §4.1: UDP for `auto`).
    fn fallback(self) -> Transport {
        match self {
            Self::One(t) => t,
            Self::Auto => Transport::Udp,
        }
    }
}

/// One SRV record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

/// Answers from a table instead of DNS (tests).
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct StaticDns {
    pub srv: HashMap<String, Vec<SrvRecord>>,
    pub hosts: HashMap<String, Vec<IpAddr>>,
}

enum Backend {
    Dns(Box<TokioAsyncResolver>),
    #[cfg(test)]
    Static(StaticDns),
}

impl Backend {
    /// SRV records and their TTL; no records is `Ok(empty)`.
    async fn srv(&self, name: &str) -> anyhow::Result<(Vec<SrvRecord>, Duration)> {
        match self {
            #[cfg(test)]
            Self::Static(t) => Ok((
                t.srv.get(name).cloned().unwrap_or_default(),
                Duration::from_secs(60),
            )),
            Self::Dns(r) => {
                let lookup = match r.srv_lookup(name).await {
                    Ok(l) => l,
                    Err(e)
                        if matches!(
                            e.kind(),
                            hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. }
                        ) =>
                    {
                        return Ok((Vec::new(), Duration::from_secs(30)))
                    }
                    Err(e) => return Err(e.into()),
                };
                let ttl = lookup
                    .as_lookup()
                    .valid_until()
                    .saturating_duration_since(Instant::now());
                let records = lookup
                    .iter()
                    .map(|r: &SRV| SrvRecord {
                        priority: r.priority(),
                        weight: r.weight(),
                        port: r.port(),
                        target: r.target().to_string().trim_end_matches('.').to_string(),
                    })
                    .collect();
                Ok((records, ttl))
            }
        }
    }

    async fn ips(&self, host: &str) -> anyhow::Result<(Vec<IpAddr>, Duration)> {
        match self {
            #[cfg(test)]
            Self::Static(t) => t
                .hosts
                .get(host)
                .cloned()
                .map(|ips| (ips, Duration::from_secs(60)))
                .ok_or_else(|| anyhow::anyhow!("NXDOMAIN {host}")),
            Self::Dns(r) => {
                let ips = r.lookup_ip(host).await?;
                let ttl = ips.valid_until().saturating_duration_since(Instant::now());
                Ok((ips.iter().collect(), ttl))
            }
        }
    }
}

/// Cached SRV resolution result.
struct CachedResolution {
    resolution: Resolution,
    resolved_at: Instant,
}

/// DNS SRV resolver with TTL-aware caching.
pub struct SrvResolver {
    backend: Backend,
    cache: RwLock<HashMap<(String, Wanted), CachedResolution>>,
}

impl SrvResolver {
    /// Create a new SRV resolver using system DNS configuration.
    pub fn new() -> anyhow::Result<Self> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Ok(Self {
            backend: Backend::Dns(Box::new(resolver)),
            cache: RwLock::new(HashMap::new()),
        })
    }

    /// A resolver answering from `table` only.
    #[cfg(test)]
    pub fn with_static(table: StaticDns) -> Self {
        Self {
            backend: Backend::Static(table),
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Resolve a SIP domain to an ordered list of server addresses.
    ///
    /// `transport` is `udp`, `tcp`, `tls` or `auto` (see [`Wanted`]). SRV
    /// first; with none published, A/AAAA of the domain at `port`.
    ///
    /// TLS is never given up for a cleartext transport: `tls` only asks
    /// `_sips._tcp`, and `auto` stops at `_sips._tcp` once the domain
    /// publishes it, even if none of its targets resolve (an error).
    pub async fn resolve(
        &self,
        domain: &str,
        port: u16,
        transport: &str,
    ) -> anyhow::Result<Resolution> {
        self.resolve_wanted(domain, port, Wanted::parse(transport))
            .await
    }

    /// [`Self::resolve`] for a parsed transport.
    pub async fn resolve_wanted(
        &self,
        domain: &str,
        port: u16,
        wanted: Wanted,
    ) -> anyhow::Result<Resolution> {
        // An IP literal names the server directly; there is nothing to look up.
        if let Ok(ip) = domain.trim_matches(['[', ']']).parse::<IpAddr>() {
            let t = wanted.fallback();
            return Ok(Resolution {
                servers: vec![ResolvedServer {
                    addr: SocketAddr::new(ip, port),
                    priority: 0,
                    weight: 0,
                    host: domain.to_string(),
                }],
                ttl: Duration::from_secs(300),
                transport: t,
            });
        }

        let key = (domain.to_ascii_lowercase(), wanted);
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(&key) {
                if let Some(left) = entry
                    .resolution
                    .ttl
                    .checked_sub(entry.resolved_at.elapsed())
                {
                    let mut r = entry.resolution.clone();
                    r.ttl = left;
                    return Ok(r);
                }
            }
        }

        let resolution = match self.resolve_srv(domain, wanted).await? {
            Some(r) => r,
            None => {
                self.resolve_a_record(domain, port, wanted.fallback())
                    .await?
            }
        };
        self.cache.write().await.insert(
            key,
            CachedResolution {
                resolution: resolution.clone(),
                resolved_at: Instant::now(),
            },
        );
        Ok(resolution)
    }

    /// Walk the SRV names for `wanted`. `None` when the domain publishes
    /// none of them (fall back to A/AAAA).
    async fn resolve_srv(
        &self,
        domain: &str,
        wanted: Wanted,
    ) -> anyhow::Result<Option<Resolution>> {
        for (name, transport) in wanted.srv_names(domain) {
            let (mut records, srv_ttl) = match self.backend.srv(&name).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::debug!(srv = %name, "SRV lookup failed: {e}");
                    if transport == Transport::Tls && wanted == Wanted::Auto {
                        // Not knowing whether TLS is published is no reason
                        // to choose cleartext.
                        anyhow::bail!("SRV lookup of {name} failed; not falling back to an unencrypted transport: {e}");
                    }
                    continue;
                }
            };
            // A target of "." means the service is decidedly not available.
            records.retain(|r| !r.target.is_empty() && r.target != ".");
            if records.is_empty() {
                continue;
            }
            let mut ttl = srv_ttl.clamp(Duration::from_secs(30), Duration::from_secs(300));
            let mut servers = Vec::new();
            for r in &records {
                match self.backend.ips(&r.target).await {
                    Ok((ips, ip_ttl)) => {
                        ttl = ttl.min(ip_ttl.max(Duration::from_secs(30)));
                        for ip in ips {
                            servers.push(ResolvedServer {
                                addr: SocketAddr::new(ip, r.port),
                                priority: r.priority,
                                weight: r.weight,
                                host: r.target.clone(),
                            });
                        }
                    }
                    Err(e) => {
                        tracing::warn!(target = %r.target, "Failed to resolve SRV target: {e}")
                    }
                }
            }
            if servers.is_empty() {
                if transport == Transport::Tls {
                    anyhow::bail!(
                        "{domain} publishes {name} but none of its targets resolve; not falling back to an unencrypted transport"
                    );
                }
                continue;
            }
            // Cached and returned by priority only: each registration does
            // its own RFC 2782 weighted shuffle (`failover::Rng`), so a shared
            // cache does not send every user to the same target.
            servers.sort_by_key(|s| s.priority);
            tracing::info!(domain = %domain, srv = %name, count = servers.len(), "SRV resolution successful");
            return Ok(Some(Resolution {
                servers,
                ttl,
                transport,
            }));
        }
        Ok(None)
    }

    /// Fallback: resolve domain as A/AAAA record with the given port.
    async fn resolve_a_record(
        &self,
        domain: &str,
        port: u16,
        transport: Transport,
    ) -> anyhow::Result<Resolution> {
        let (ips, ttl) = self.backend.ips(domain).await?;
        let servers: Vec<ResolvedServer> = ips
            .into_iter()
            .map(|ip| ResolvedServer {
                addr: SocketAddr::new(ip, port),
                priority: 0,
                weight: 0,
                host: domain.to_string(),
            })
            .collect();
        if servers.is_empty() {
            anyhow::bail!("No A/AAAA records found for {}", domain);
        }
        tracing::info!(domain = %domain, count = servers.len(), "A record fallback resolution");
        Ok(Resolution {
            servers,
            ttl: ttl.max(Duration::from_secs(30)),
            transport,
        })
    }
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
            host: "pbx.example.com".into(),
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

    /// (priority, port, target) of one SRV record.
    type Rec<'a> = (u16, u16, &'a str);

    fn table(srv: &[(&str, &[Rec<'_>])], hosts: &[(&str, &str)]) -> SrvResolver {
        let mut t = StaticDns::default();
        for (name, recs) in srv {
            t.srv.insert(
                name.to_string(),
                recs.iter()
                    .map(|(prio, port, target)| SrvRecord {
                        priority: *prio,
                        weight: 50,
                        port: *port,
                        target: target.to_string(),
                    })
                    .collect(),
            );
        }
        for (h, ip) in hosts {
            t.hosts.insert(h.to_string(), vec![ip.parse().unwrap()]);
        }
        SrvResolver::with_static(t)
    }

    #[tokio::test]
    async fn auto_prefers_sips_and_keeps_the_target_names() {
        let r = table(
            &[
                (
                    "_sips._tcp.sip.test",
                    &[(10, 5061, "node1.sip.test"), (10, 5061, "node2.sip.test")],
                ),
                ("_sip._udp.sip.test", &[(10, 5060, "node1.sip.test")]),
            ],
            &[
                ("node1.sip.test", "10.0.0.1"),
                ("node2.sip.test", "10.0.0.2"),
            ],
        );
        let res = r.resolve("sip.test", 5060, "auto").await.unwrap();
        assert_eq!(res.transport, Transport::Tls);
        assert_eq!(res.servers.len(), 2);
        assert!(res.servers.iter().all(|s| s.addr.port() == 5061));
        let hosts: Vec<_> = res.servers.iter().map(|s| s.host.as_str()).collect();
        assert!(hosts.contains(&"node1.sip.test") && hosts.contains(&"node2.sip.test"));
    }

    #[tokio::test]
    async fn auto_walks_tls_then_tcp_then_udp() {
        let r = table(
            &[
                ("_sip._tcp.a.test", &[(10, 5060, "n.a.test")]),
                ("_sip._udp.a.test", &[(10, 5060, "n.a.test")]),
            ],
            &[("n.a.test", "10.0.0.1")],
        );
        assert_eq!(
            r.resolve("a.test", 5060, "auto").await.unwrap().transport,
            Transport::Tcp
        );
        let r = table(
            &[("_sip._udp.b.test", &[(10, 5060, "n.b.test")])],
            &[("n.b.test", "10.0.0.1")],
        );
        assert_eq!(
            r.resolve("b.test", 5060, "auto").await.unwrap().transport,
            Transport::Udp
        );
    }

    #[tokio::test]
    async fn a_published_tls_service_is_never_traded_for_cleartext() {
        // _sips is published but its target does not resolve: an error, not UDP.
        let r = table(
            &[
                ("_sips._tcp.c.test", &[(10, 5061, "gone.c.test")]),
                ("_sip._udp.c.test", &[(10, 5060, "n.c.test")]),
            ],
            &[("n.c.test", "10.0.0.1"), ("c.test", "10.0.0.9")],
        );
        assert!(r.resolve("c.test", 5060, "auto").await.is_err());
        assert!(r.resolve("c.test", 5061, "tls").await.is_err());
        // Explicit UDP still works for a device configured for it.
        assert_eq!(
            r.resolve("c.test", 5060, "udp").await.unwrap().transport,
            Transport::Udp
        );
    }

    #[tokio::test]
    async fn tls_without_srv_uses_the_domain_at_the_given_port() {
        let r = table(&[], &[("d.test", "10.0.0.4")]);
        let res = r.resolve("d.test", 5061, "tls").await.unwrap();
        assert_eq!(res.transport, Transport::Tls);
        assert_eq!(res.servers[0].addr.to_string(), "10.0.0.4:5061");
        assert_eq!(res.servers[0].host, "d.test");
        // auto with nothing published is UDP (RFC 3263 §4.1).
        assert_eq!(
            r.resolve("d.test", 5060, "auto").await.unwrap().transport,
            Transport::Udp
        );
    }
}

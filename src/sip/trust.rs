//! Which addresses may send SIP to the gateway.
//!
//! A message is accepted when its source IP is one the PBX/registrar (or an
//! outgoing call's server) resolved to, or falls in the operator's
//! `TRUSTED_SIP_SOURCES` allowlist. The source port is not checked: a PBX
//! bound to 0.0.0.0, behind a floating IP or spread over several nodes may
//! send from another address or port than the one it is reached on. Spoofed
//! in-dialog requests are still stopped by dialog matching (Call-ID and both
//! tags) on the socket that owns the dialog.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// Operator allowlist of IPs and CIDR ranges.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TrustedSources {
    nets: Vec<(IpAddr, u8)>,
}

impl TrustedSources {
    /// Parse a comma-separated list of IPs and CIDRs (`10.0.0.0/8`,
    /// `203.0.113.7`, `2001:db8::/32`). Blank entries are ignored.
    pub fn parse(list: &str) -> anyhow::Result<Self> {
        let mut nets = Vec::new();
        for entry in list.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            let (ip, len) = match entry.split_once('/') {
                Some((ip, len)) => {
                    let ip: IpAddr = ip
                        .trim()
                        .parse()
                        .map_err(|_| anyhow::anyhow!("invalid IP in {entry:?}"))?;
                    let len: u8 = len
                        .trim()
                        .parse()
                        .map_err(|_| anyhow::anyhow!("invalid prefix length in {entry:?}"))?;
                    (ip, len)
                }
                None => {
                    let ip: IpAddr = entry
                        .parse()
                        .map_err(|_| anyhow::anyhow!("invalid IP {entry:?}"))?;
                    (ip, if ip.is_ipv4() { 32 } else { 128 })
                }
            };
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if len > max {
                anyhow::bail!("prefix length too long in {entry:?}");
            }
            nets.push((ip.to_canonical(), len));
        }
        Ok(Self { nets })
    }

    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    /// Whether `ip` is in one of the allowlisted networks.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.nets.iter().any(|&(net, len)| in_prefix(ip, net, len))
    }
}

fn in_prefix(ip: IpAddr, net: IpAddr, len: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// The sources one socket accepts: its peer's resolved IPs plus the
/// allowlist.
#[derive(Debug, Default, Clone)]
pub struct SourcePolicy {
    ips: Vec<IpAddr>,
    allow: Arc<TrustedSources>,
}

impl SourcePolicy {
    pub fn new(ips: impl IntoIterator<Item = IpAddr>, allow: Arc<TrustedSources>) -> Self {
        Self {
            ips: ips.into_iter().map(|ip| ip.to_canonical()).collect(),
            allow,
        }
    }

    /// Accept SIP from this IP too (tests only).
    #[cfg(test)]
    pub fn add_ip(&mut self, ip: IpAddr) {
        self.ips.push(ip.to_canonical());
    }

    /// Whether a packet from `from` may be processed (any source port).
    pub fn admits(&self, from: SocketAddr) -> bool {
        let ip = from.ip().to_canonical();
        self.ips.contains(&ip) || self.allow.contains(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn resolved_ips_are_admitted_on_any_port() {
        let p = SourcePolicy::new(["203.0.113.7".parse().unwrap()], Arc::default());
        assert!(p.admits(addr("203.0.113.7:5060")));
        assert!(p.admits(addr("203.0.113.7:41234")));
        assert!(!p.admits(addr("203.0.113.8:5060")));
        assert!(!p.admits(addr("127.0.0.1:5060")));
        // IPv4-mapped IPv6 sources are the same address.
        assert!(p.admits(addr("[::ffff:203.0.113.7]:5060")));
    }

    #[test]
    fn allowlist_admits_cidrs_and_single_ips() {
        let allow =
            Arc::new(TrustedSources::parse(" 10.20.0.0/16, 198.51.100.9 ,2001:db8::/32,").unwrap());
        let p = SourcePolicy::new(["203.0.113.7".parse().unwrap()], allow);
        assert!(p.admits(addr("10.20.0.1:5060")));
        assert!(p.admits(addr("10.20.255.254:1")));
        assert!(!p.admits(addr("10.21.0.1:5060")));
        assert!(p.admits(addr("198.51.100.9:5080")));
        assert!(!p.admits(addr("198.51.100.10:5080")));
        assert!(p.admits(addr("[2001:db8::1]:5060")));
        assert!(!p.admits(addr("[2001:db9::1]:5060")));
        assert!(p.admits(addr("203.0.113.7:9")));
    }

    #[test]
    fn allowlist_parsing() {
        assert!(TrustedSources::parse("").unwrap().is_empty());
        assert!(TrustedSources::parse(" , ").unwrap().is_empty());
        assert!(TrustedSources::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
        for bad in [
            "10.0.0.0/33",
            "not-an-ip",
            "10.0.0.0/x",
            "10.0.0.1/",
            "::/129",
        ] {
            assert!(TrustedSources::parse(bad).is_err(), "{bad}");
        }
    }
}

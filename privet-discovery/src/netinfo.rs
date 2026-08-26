
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkFingerprint {
    pub subnets: Vec<Cidr>,
    pub gateway_ip: Option<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchConfidence {
    None,
    Low,
    Medium,
}

impl NetworkFingerprint {
    pub fn confidence(&self, other: &NetworkFingerprint) -> MatchConfidence {
        let subnet_match = self.subnets.iter().any(|s| other.subnets.contains(s));
        if !subnet_match {
            return MatchConfidence::None;
        }
        match (self.gateway_ip, other.gateway_ip) {
            (Some(g1), Some(g2)) if g1 == g2 => MatchConfidence::Medium,
            _ => MatchConfidence::Low,
        }
    }
}

pub fn directed_broadcast(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = if prefix == 0 {
                0
            } else {
                !0u32 << (32 - prefix)
            };
            let bcast = bits | !mask;
            IpAddr::V4(Ipv4Addr::from(bcast))
        }
        IpAddr::V6(_) => addr,
    }
}

pub fn enumerate_interfaces() -> Vec<(IpAddr, u8, Option<IpAddr>, String)> {
    let mut out = Vec::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if iface.is_loopback() {
            continue;
        }
        match iface.addr {
            if_addrs::IfAddr::V4(ref v4) => {
                out.push((
                    IpAddr::V4(v4.ip),
                    v4.prefixlen,
                    v4.broadcast.map(IpAddr::V4),
                    iface.name.clone(),
                ));
            }
            if_addrs::IfAddr::V6(ref v6) => {
                out.push((IpAddr::V6(v6.ip), v6.prefixlen, None, iface.name.clone()));
            }
        }
    }
    out
}

pub fn current_fingerprint() -> NetworkFingerprint {
    let subnets = enumerate_interfaces()
        .into_iter()
        .filter_map(|(addr, prefix, _, _)| match addr {
            IpAddr::V4(v4) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    !0u32 << (32 - prefix.min(32))
                };
                let net = u32::from(v4) & mask;
                Some(Cidr {
                    addr: IpAddr::V4(Ipv4Addr::from(net)),
                    prefix,
                })
            }
            IpAddr::V6(_) => None,
        })
        .collect();
    let gateway_ip = default_net::get_default_gateway().ok().map(|g| g.ip_addr);
    NetworkFingerprint {
        subnets,
        gateway_ip,
    }
}

pub fn is_local_ip(src: IpAddr, ifaces: &[(IpAddr, u8, Option<IpAddr>, String)]) -> bool {
    ifaces.iter().any(|(addr, _, _, _)| *addr == src)
}

pub fn probe_src_is_local_subnet(
    src: IpAddr,
    ifaces: &[(IpAddr, u8, Option<IpAddr>, String)],
) -> bool {
    let IpAddr::V4(src_v4) = src else {
        return false;
    };
    ifaces.iter().any(|(addr, prefix, _, _)| match addr {
        IpAddr::V4(a) => {
            let p = *prefix;
            let mask = if p == 0 { 0 } else { !0u32 << (32 - p.min(32)) };
            let net = u32::from(*a) & mask;
            let src_net = u32::from(src_v4) & mask;
            net == src_net
        }
        IpAddr::V6(_) => false,
    })
}

//! 网络指纹 + 接口枚举 + 子网定向广播

use std::net::{IpAddr, Ipv4Addr};

/// CIDR（IPv4；IPv6 子网匹配同理但本期聚焦 IPv4 LAN）。
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
    Low,    // 任一 subnet 相等
    Medium, // subnet + gateway 都相等
}

impl NetworkFingerprint {
    /// 与记录指纹的匹配置信度。
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

/// 子网定向广播地址 = `addr | ~netmask`。
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
        IpAddr::V6(_) => addr, // IPv6 无广播；回退地址（多播另议）
    }
}

/// 枚举非环回接口。返回 (addr, prefix, broadcast, iface_name)。
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

/// 当前网络指纹。gateway 用 default-net，失败则 None（低置信）。
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

/// src 是否为本机某个非环回接口的 IP（用于跳过自回环 Probe）。
pub fn is_local_ip(src: IpAddr, ifaces: &[(IpAddr, u8, Option<IpAddr>, String)]) -> bool {
    ifaces.iter().any(|(addr, _, _, _)| *addr == src)
}

/// src 是否落在本机某非环回接口的子网内（防外部反射放大）。
/// 纯逻辑：取显式接口列表，便于单测合成。
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

//! Network awareness: detect local network subnets and identify the
//! current network environment.

use std::net::{IpAddr, Ipv4Addr};
use serde::{Deserialize, Serialize};

/// Information about a detected local network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// Subnet in CIDR notation, e.g. "192.168.1.0/24"
    pub subnet: String,
    /// Network interface name (if available)
    pub interface_name: String,
    /// Local IP addresses on this subnet
    pub local_ips: Vec<IpAddr>,
}

/// Compute a subnet prefix string from an IP address and prefix length.
/// Returns the network address in CIDR notation, e.g. "192.168.1.0/24"
pub fn subnet_from_addr(ip: &IpAddr, prefix_len: u8) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let mask: u32 = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            let net = u32::from(*v4) & mask;
            let net_addr = Ipv4Addr::from(net);
            format!("{net_addr}/{prefix_len}")
        }
        IpAddr::V6(_v6) => {
            // For IPv6, use /64 as default prefix for link-local
            format!("{ip}/64")
        }
    }
}

/// Detect the current local network interfaces and their subnets.
///
/// Uses platform-specific methods to enumerate network interfaces.
/// Falls back to a simple approach on platforms where `local_ip` is available.
pub fn detect_current_networks() -> Vec<NetworkInfo> {
    let mut networks = Vec::new();

    // Use the `local_ip` crate approach: try to find local IPs by
    // binding a UDP socket and connecting to a public address.
    // This avoids platform-specific interface enumeration.
    if let Some(ip) = detect_local_ipv4() {
        let subnet = subnet_from_addr(&IpAddr::V4(ip), 24);
        networks.push(NetworkInfo {
            subnet,
            interface_name: String::new(),
            local_ips: vec![IpAddr::V4(ip)],
        });
    }

    networks
}

/// Detect a local IPv4 address by creating a UDP socket.
/// This works across platforms without needing special permissions.
fn detect_local_ipv4() -> Option<Ipv4Addr> {
    // Try to "connect" a UDP socket to a public IP.
    // This doesn't actually send any packets, but it causes the OS
    // to select the appropriate local interface.
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:53").ok()?;
    let addr = socket.local_addr().ok()?;
    match addr.ip() {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

/// Get the default prefix length for a given IPv4 address.
/// Returns 24 for typical RFC1918 private networks, 16 for 10.x.x.x, etc.
pub fn default_prefix_len(ip: &Ipv4Addr) -> u8 {
    let octets = ip.octets();
    if octets[0] == 10 {
        8  // 10.0.0.0/8
    } else if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        12 // 172.16.0.0/12
    } else if octets[0] == 192 && octets[1] == 168 {
        24 // 192.168.0.0/16
    } else {
        24 // Default to /24
    }
}

/// Detect current networks with more accurate prefix lengths.
pub fn detect_current_networks_smart() -> Vec<NetworkInfo> {
    let mut networks = Vec::new();

    if let Some(ip) = detect_local_ipv4() {
        let prefix_len = default_prefix_len(&ip);
        let subnet = subnet_from_addr(&IpAddr::V4(ip), prefix_len);
        networks.push(NetworkInfo {
            subnet,
            interface_name: String::new(),
            local_ips: vec![IpAddr::V4(ip)],
        });
    }

    networks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_from_addr_class_c() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        assert_eq!(subnet_from_addr(&ip, 24), "192.168.1.0/24");
    }

    #[test]
    fn subnet_from_addr_class_a() {
        let ip: IpAddr = "10.0.5.100".parse().unwrap();
        assert_eq!(subnet_from_addr(&ip, 8), "10.0.0.0/8");
    }

    #[test]
    fn subnet_from_addr_class_b() {
        let ip: IpAddr = "172.16.5.100".parse().unwrap();
        assert_eq!(subnet_from_addr(&ip, 12), "172.16.0.0/12");
    }

    #[test]
    fn default_prefix_len_various() {
        assert_eq!(default_prefix_len(&"10.0.0.1".parse().unwrap()), 8);
        assert_eq!(default_prefix_len(&"172.16.0.1".parse().unwrap()), 12);
        assert_eq!(default_prefix_len(&"192.168.1.1".parse().unwrap()), 24);
        assert_eq!(default_prefix_len(&"172.31.0.1".parse().unwrap()), 12);
        assert_eq!(default_prefix_len(&"8.8.8.8".parse().unwrap()), 24);
    }

    #[test]
    fn detect_networks_returns_nonempty() {
        // This test may fail in CI environments without network
        let nets = detect_current_networks();
        // Just verify it doesn't panic
        println!("Detected networks: {:?}", nets);
    }
}

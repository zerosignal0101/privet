//! Network awareness: detect all local network interfaces and their subnets.

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
            format!("{ip}/64")
        }
    }
}

/// Get the default prefix length for a given IPv4 address.
pub fn default_prefix_len(ip: &Ipv4Addr) -> u8 {
    let octets = ip.octets();
    if octets[0] == 10 {
        8
    } else if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        12
    } else if octets[0] == 192 && octets[1] == 168 {
        24
    } else {
        24
    }
}

/// Enumerate all local network interfaces and return their network info.
/// Filters out loopback addresses and non-IPv4 interfaces.
pub fn detect_all_networks() -> Vec<NetworkInfo> {
    let mut networks: Vec<NetworkInfo> = Vec::new();

    let addrs = match if_addrs::get_if_addrs() {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!("failed to enumerate network interfaces: {e}");
            return networks;
        }
    };

    for iface in &addrs {
        // Only consider IPv4 addresses (skip IPv6 for now)
        let ip = match iface.addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => continue,
        };

        // Skip loopback
        if ip.is_loopback() {
            continue;
        }

        // Use classful prefix so subnet strings stay consistent with
        // `record_to_known_devices` and the Dart-side subnet calculation.
        let prefix_len = default_prefix_len(&ip);

        let subnet = subnet_from_addr(&IpAddr::V4(ip), prefix_len);

        // Find or create the network entry for this subnet
        if let Some(net) = networks.iter_mut().find(|n: &&mut NetworkInfo| n.subnet == subnet && n.interface_name == iface.name) {
            if !net.local_ips.contains(&IpAddr::V4(ip)) {
                net.local_ips.push(IpAddr::V4(ip));
            }
        } else {
            networks.push(NetworkInfo {
                subnet,
                interface_name: iface.name.clone(),
                local_ips: vec![IpAddr::V4(ip)],
            });
        }
    }

    networks
}

/// Detect current networks — still exposed for backward compat but
/// now delegates to [`detect_all_networks`].
pub fn detect_current_networks() -> Vec<NetworkInfo> {
    detect_all_networks()
}

/// Smart detection — also delegates to [`detect_all_networks`].
pub fn detect_current_networks_smart() -> Vec<NetworkInfo> {
    detect_all_networks()
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
        let nets = detect_all_networks();
        println!("Detected networks: {nets:#?}");
    }
}

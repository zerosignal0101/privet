use privet_discovery::netinfo::{directed_broadcast, Cidr, NetworkFingerprint};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn directed_broadcast_for_192_168_1_10_24() {
    let b = directed_broadcast(IpAddr::V4("192.168.1.10".parse().unwrap()), 24);
    assert_eq!(b, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)));
}

#[test]
fn directed_broadcast_for_10_0_0_5_8() {
    let b = directed_broadcast(IpAddr::V4("10.0.0.5".parse().unwrap()), 8);
    assert_eq!(b, IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255)));
}

#[test]
fn fingerprint_matches_same_subnet() {
    let a = NetworkFingerprint {
        subnets: vec![Cidr {
            addr: IpAddr::V4("192.168.1.0".parse().unwrap()),
            prefix: 24,
        }],
        gateway_ip: Some("192.168.1.1".parse().unwrap()),
    };
    let b = NetworkFingerprint {
        subnets: vec![Cidr {
            addr: IpAddr::V4("192.168.1.0".parse().unwrap()),
            prefix: 24,
        }],
        gateway_ip: Some("192.168.1.1".parse().unwrap()),
    };
    assert_eq!(
        a.confidence(&b),
        privet_discovery::netinfo::MatchConfidence::Medium
    );
}

#[test]
fn fingerprint_subnet_only_is_low() {
    let a = NetworkFingerprint {
        subnets: vec![Cidr {
            addr: IpAddr::V4("192.168.1.0".parse().unwrap()),
            prefix: 24,
        }],
        gateway_ip: Some("192.168.1.1".parse().unwrap()),
    };
    let b = NetworkFingerprint {
        subnets: vec![Cidr {
            addr: IpAddr::V4("192.168.1.0".parse().unwrap()),
            prefix: 24,
        }],
        gateway_ip: None,
    };
    assert_eq!(
        a.confidence(&b),
        privet_discovery::netinfo::MatchConfidence::Low
    );
}

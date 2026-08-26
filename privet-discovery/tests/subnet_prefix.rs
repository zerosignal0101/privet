
use privet_discovery::netinfo::{Cidr, NetworkFingerprint};
use std::net::IpAddr;

#[test]
fn same_subnet_slash16_detected() {
    let net = NetworkFingerprint {
        subnets: vec![Cidr {
            addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            prefix: 16,
        }],
        gateway_ip: None,
    };
    assert!(
        privet_discovery::direct::shares_subnet("10.0.5.9".parse().unwrap(), &net),
        "10.0.5.9 with /16 should match"
    );
    assert!(
        !privet_discovery::direct::shares_subnet("10.1.0.1".parse().unwrap(), &net),
        "10.1.0.1 with /16 should not match 10.0.0.0/16"
    );
}

#[test]
fn subnet_prefix_zero_detects_everything() {
    let net = NetworkFingerprint {
        subnets: vec![Cidr {
            addr: "0.0.0.0".parse::<IpAddr>().unwrap(),
            prefix: 0,
        }],
        gateway_ip: None,
    };
    assert!(
        privet_discovery::direct::shares_subnet("192.168.1.1".parse().unwrap(), &net),
        "prefix 0 should match any address"
    );
}

#[test]
fn prefix_exactly_32_no_panic() {
    let net = NetworkFingerprint {
        subnets: vec![Cidr {
            addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            prefix: 32,
        }],
        gateway_ip: None,
    };
    assert!(
        privet_discovery::direct::shares_subnet("10.0.0.1".parse().unwrap(), &net),
        "/32 should match exact IP"
    );
    assert!(
        !privet_discovery::direct::shares_subnet("10.0.0.2".parse().unwrap(), &net),
        "/32 should not match different IP"
    );
}

#[test]
fn current_fingerprint_prefix_zero_no_panic() {
    let net = NetworkFingerprint {
        subnets: vec![Cidr {
            addr: "0.0.0.0".parse::<IpAddr>().unwrap(),
            prefix: 0,
        }],
        gateway_ip: None,
    };
    let _ = privet_discovery::direct::shares_subnet("10.0.0.1".parse().unwrap(), &net);
}

#[test]
fn shares_subnet_is_public() {
    let net = NetworkFingerprint {
        subnets: vec![Cidr {
            addr: "10.0.0.1".parse::<IpAddr>().unwrap(),
            prefix: 8,
        }],
        gateway_ip: None,
    };
    assert!(
        privet_discovery::direct::shares_subnet("10.5.5.5".parse().unwrap(), &net),
        "/8 should match 10.x.x.x"
    );
}

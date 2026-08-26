use async_trait::async_trait;
use privet_discovery::direct::{
    select_candidates, ConnectOutcome, KnownAddressRecord, PeerConnector,
};
use privet_discovery::netinfo::{Cidr, NetworkFingerprint};
use privet_discovery::peer::{CandidateAddress, PeerRecord, PeerState};
use std::net::IpAddr;

fn cand(ip: &str, last_ms: u64) -> CandidateAddress {
    CandidateAddress {
        ip: ip.parse().unwrap(),
        quic_port: 47808,
        tcp_port: 47810,
        heard_iface: None,
        last_seen_ms: last_ms,
    }
}

#[test]
fn prefer_same_subnet_then_last_seen() {
    let rec = PeerRecord {
        device_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
        state: PeerState::Live,
        candidates: vec![
            cand("10.0.0.5", 100),
            cand("192.168.1.5", 200),
            cand("192.168.1.9", 300),
        ],
        device_name: "n".into(),
        last_beacon_ms: 0,
    };
    let net = NetworkFingerprint {
        subnets: vec![Cidr {
            addr: "192.168.1.0".parse().unwrap(),
            prefix: 24,
        }],
        gateway_ip: None,
    };
    let ordered = select_candidates(&rec, &net);
    assert_eq!(ordered[0].ip, "192.168.1.9".parse::<IpAddr>().unwrap());
    assert_eq!(ordered[1].ip, "192.168.1.5".parse::<IpAddr>().unwrap());
    assert_eq!(ordered[2].ip, "10.0.0.5".parse::<IpAddr>().unwrap());
}

struct MockConnector {
    success_ip: IpAddr,
}

#[async_trait]
impl PeerConnector for MockConnector {
    async fn try_connect(&self, addr: IpAddr, _quic_port: u16, _tcp_port: u16) -> ConnectOutcome {
        if addr == self.success_ip {
            ConnectOutcome::Ok { used_addr: addr }
        } else {
            ConnectOutcome::Fail
        }
    }
}

#[tokio::test]
async fn probe_recent_stops_at_first_success() {
    let connector = MockConnector {
        success_ip: "10.0.0.2".parse().unwrap(),
    };
    let addrs: Vec<KnownAddressRecord> = vec![
        KnownAddressRecord {
            addr: "10.0.0.1".parse().unwrap(),
            quic_port: 47808,
            tcp_port: 47810,
            subnet_cidr: "10.0.0.0/24".into(),
            last_seen_ms: 0,
            success_count: 0,
            fail_count: 0,
        },
        KnownAddressRecord {
            addr: "10.0.0.2".parse().unwrap(),
            quic_port: 47808,
            tcp_port: 47810,
            subnet_cidr: "10.0.0.0/24".into(),
            last_seen_ms: 0,
            success_count: 0,
            fail_count: 0,
        },
    ];
    let outcome = privet_discovery::direct::probe_recent(
        &connector,
        &addrs,
        std::time::Duration::from_millis(100),
        8,
    )
    .await;
    assert!(matches!(outcome, Some(ConnectOutcome::Ok { .. })));
    if let Some(ConnectOutcome::Ok { used_addr }) = outcome {
        assert_eq!(used_addr, "10.0.0.2".parse::<IpAddr>().unwrap());
    } else {
        panic!("expected Ok outcome");
    }
}

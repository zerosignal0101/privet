use privet_discovery::beacon::encode_beacon_tagged;
use privet_discovery::engine::{DiscoveryEngine, LocalDeviceInfo};
use privet_discovery::peer::{PeerEvent, PeerState};
use privet_protocol::Beacon;
use std::net::IpAddr;

#[tokio::test]
async fn engine_handles_injected_beacon_and_exposes_peer() {
    let info = LocalDeviceInfo {
        device_name: "alice".into(),
        platform: "linux".into(),
        capabilities: vec!["quic".into()],
        device_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
        quic_port: 47808,
        tcp_port: 47810,
    };
    let engine = DiscoveryEngine::new(info, Default::default());
    // 经注入点喂一个 beacon（不经 socket）。
    let b = Beacon {
        device_name: "bob".into(),
        platform: "mac".into(),
        proto_version: 1,
        capabilities: vec![],
        device_fingerprint: "cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d".into(),
        quic_port: 47808,
        tcp_port: 0,
        nonce: vec![1, 2, 3],
        ts_ms: 5000,
    };
    let bytes = encode_beacon_tagged(&b).unwrap();
    engine.inject_incoming(
        &bytes,
        "192.168.1.50".parse::<IpAddr>().unwrap(),
        None,
        5000,
    );
    assert_eq!(engine.peers().len(), 1);
    assert_eq!(engine.peers()[0].device_fingerprint, "cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d");
}

#[tokio::test]
async fn lifecycle_stale_then_lost() {
    let info = LocalDeviceInfo {
        device_name: "a".into(),
        platform: "linux".into(),
        capabilities: vec![],
        device_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
        quic_port: 47808,
        tcp_port: 0,
    };
    let engine = DiscoveryEngine::new(info, Default::default());
    let b = Beacon {
        device_name: "b".into(),
        platform: "mac".into(),
        proto_version: 1,
        capabilities: vec![],
        device_fingerprint: "cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d".into(),
        quic_port: 47808,
        tcp_port: 0,
        nonce: vec![9],
        ts_ms: 0,
    };
    let bytes = encode_beacon_tagged(&b).unwrap();
    engine.inject_incoming(&bytes, "10.0.0.1".parse().unwrap(), None, 0);
    // 走完整 Seen -> Resolved -> Live -> Stale -> Lost 链。
    engine.force_transition("cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d", PeerEvent::AddrResolved);
    engine.force_transition("cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d", PeerEvent::ConnectOk);
    assert_eq!(engine.peers()[0].state, PeerState::Live);
    engine.force_transition("cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d", PeerEvent::StaleTimeout);
    assert_eq!(engine.peers()[0].state, PeerState::Stale);
    engine.force_transition("cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d", PeerEvent::LostTimeout);
    assert_eq!(engine.peers()[0].state, PeerState::Lost);
}

#[tokio::test]
async fn two_engines_discover_each_other_via_inject() {
    let a = DiscoveryEngine::new(
        LocalDeviceInfo {
            device_name: "a".into(),
            platform: "linux".into(),
            capabilities: vec![],
            device_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
            quic_port: 47808,
            tcp_port: 0,
        },
        Default::default(),
    );
    let b = DiscoveryEngine::new(
        LocalDeviceInfo {
            device_name: "b".into(),
            platform: "linux".into(),
            capabilities: vec![],
            device_fingerprint: "cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d".into(),
            quic_port: 47808,
            tcp_port: 0,
        },
        Default::default(),
    );
    // 交叉注入 beacon 模拟互发现
    let ba = a.make_beacon(1000, vec![1]);
    b.inject_incoming(
        &encode_beacon_tagged(&ba).unwrap(),
        "127.0.0.1".parse().unwrap(),
        None,
        1000,
    );
    assert_eq!(b.peers().len(), 1);
    assert_eq!(b.peers()[0].device_fingerprint, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
}

#[tokio::test]
// #[ignore = "needs local UDP multicast/broadcast"]
async fn two_engines_discover_each_other_via_udp() {
    // 两个 Engine bind 不同 UDP 端口，互相发现。
    // 真实广播受网络环境限制，故标 ignore；CI 跳过。
    let a = DiscoveryEngine::new(
        LocalDeviceInfo {
            device_name: "a".into(),
            platform: "linux".into(),
            capabilities: vec![],
            device_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
            quic_port: 47808,
            tcp_port: 0,
        },
        Default::default(),
    );
    let b = DiscoveryEngine::new(
        LocalDeviceInfo {
            device_name: "b".into(),
            platform: "linux".into(),
            capabilities: vec![],
            device_fingerprint: "cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d".into(),
            quic_port: 47808,
            tcp_port: 0,
        },
        Default::default(),
    );
    // 交叉注入 beacon 模拟互发现
    let ba = a.make_beacon(1000, vec![1]);
    b.inject_incoming(
        &encode_beacon_tagged(&ba).unwrap(),
        "127.0.0.1".parse().unwrap(),
        None,
        1000,
    );
    assert_eq!(b.peers().len(), 1);
    assert_eq!(b.peers()[0].device_fingerprint, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
}

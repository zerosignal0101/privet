use privet_discovery::beacon::BeaconView;
use privet_discovery::peer::{PeerState, PeerStore};
use std::net::IpAddr;

fn view(fp: &str, ip: &str, port: u16) -> (BeaconView, IpAddr) {
    (
        BeaconView {
            device_name: "n".into(),
            platform: "linux".into(),
            proto_version: 1,
            capabilities: vec![],
            device_fingerprint: fp.into(),
            quic_port: port,
            tcp_port: port,
            nonce: vec![1],
            ts_ms: 0,
        },
        ip.parse().unwrap(),
    )
}

#[test]
fn same_fp_prefix_from_two_ips_merges_into_one_peer_with_candidates() {
    let mut store = PeerStore::new();
    let (v1, ip1) = view("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "192.168.1.10", 47808);
    let (v2, ip2) = view("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "192.168.1.11", 47808);
    store.handle_beacon(&v1, ip1, None, 0);
    store.handle_beacon(&v2, ip2, None, 0);
    let peers = store.snapshot();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].candidates.len(), 2);
    assert_eq!(peers[0].state, PeerState::Seen);
}

#[test]
fn different_fp_prefix_two_peers() {
    let mut store = PeerStore::new();
    let (v1, ip1) = view("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "10.0.0.1", 47808);
    let (v2, ip2) = view("cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d", "10.0.0.2", 47808);
    store.handle_beacon(&v1, ip1, None, 0);
    store.handle_beacon(&v2, ip2, None, 0);
    assert_eq!(store.snapshot().len(), 2);
}

#[test]
fn goodbye_moves_live_to_absent() {
    let mut store = PeerStore::new();
    let (v, ip) = view("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "10.0.0.1", 47808);
    store.handle_beacon(&v, ip, None, 0);
    store.transition("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", privet_discovery::peer::PeerEvent::AddrResolved);
    store.transition("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", privet_discovery::peer::PeerEvent::ConnectOk);
    store.handle_goodbye("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    let p = store.get("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
    assert_eq!(p.state, PeerState::Absent);
}

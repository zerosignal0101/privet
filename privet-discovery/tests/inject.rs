use privet_discovery::beacon::encode_beacon_tagged;
use privet_discovery::peer::{PeerState, PeerStore};
use privet_discovery::udp::{handle_incoming_datagram, NonceCache, RateLimiter};
use privet_protocol::Beacon;
use std::net::IpAddr;

fn beacon(fp: &str, nonce: &[u8], ts: u64) -> Beacon {
    Beacon {
        device_name: "n".into(),
        platform: "linux".into(),
        proto_version: 1,
        capabilities: vec![],
        device_fingerprint: fp.into(),
        quic_port: 47808,
        tcp_port: 47810,
        nonce: nonce.to_vec(),
        ts_ms: ts,
    }
}

fn tagged_bytes(b: &Beacon) -> Vec<u8> {
    encode_beacon_tagged(b).unwrap()
}

#[test]
fn handle_valid_beacon_adds_peer() {
    let mut store = PeerStore::new();
    let mut nonce = NonceCache::new();
    let mut rl = RateLimiter::new();
    let b = beacon("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", b"nonce1", 1000);
    let bytes = tagged_bytes(&b);
    handle_incoming_datagram(
        &mut store,
        &bytes,
        "10.0.0.1".parse().unwrap(),
        None,
        1000,
        &mut nonce,
        &mut rl,
    );
    assert_eq!(store.snapshot().len(), 1);
    assert_eq!(store.get("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap().state, PeerState::Seen);
}

#[test]
fn handle_replay_nonce_dropped() {
    let mut store = PeerStore::new();
    let mut nonce = NonceCache::new();
    let mut rl = RateLimiter::new();
    let b = beacon("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", b"nonce1", 1000);
    let bytes = tagged_bytes(&b);
    handle_incoming_datagram(
        &mut store,
        &bytes,
        "10.0.0.1".parse().unwrap(),
        None,
        1000,
        &mut nonce,
        &mut rl,
    );
    handle_incoming_datagram(
        &mut store,
        &bytes,
        "10.0.0.1".parse().unwrap(),
        None,
        1000,
        &mut nonce,
        &mut rl,
    );
    assert_eq!(store.snapshot().len(), 1);
}

#[test]
fn rate_limit_drops_excess_from_one_source() {
    let mut store = PeerStore::new();
    let mut nonce = NonceCache::new();
    let mut rl = RateLimiter::new();
    let src: IpAddr = "10.0.0.1".parse().unwrap();
    for i in 0..15 {
        let b = beacon(&format!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbee{i:x}"), &[i as u8], 1000);
        let bytes = tagged_bytes(&b);
        handle_incoming_datagram(&mut store, &bytes, src, None, 1000, &mut nonce, &mut rl);
    }
    assert_eq!(store.snapshot().len(), 10);
}

use privet_discovery::beacon::encode_beacon;
use privet_discovery::inject::{inject_beacon, CapturedSink};
use privet_discovery::udp::Outgoing;

#[tokio::test]
async fn capture_outgoing_collects_sent_datagrams() {
    let sink = CapturedSink::new();
    let b = Beacon {
        device_name: "n".into(),
        platform: "linux".into(),
        proto_version: 1,
        capabilities: vec![],
        device_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
        quic_port: 47808,
        tcp_port: 47810,
        nonce: vec![1],
        ts_ms: 1000,
    };
    let bytes = encode_beacon(&b).unwrap();
    sink.send_to(&bytes, "255.255.255.255:47809".parse().unwrap())
        .await
        .unwrap();
    let captured = sink.captured();
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].1,
        "255.255.255.255:47809"
            .parse::<std::net::SocketAddr>()
            .unwrap()
    );
}

#[test]
fn inject_beacon_adds_peer_without_socket() {
    let mut store = PeerStore::new();
    let mut nonce = NonceCache::new();
    let mut rl = RateLimiter::new();
    let b = Beacon {
        device_name: "n".into(),
        platform: "linux".into(),
        proto_version: 1,
        capabilities: vec![],
        device_fingerprint: "cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d".into(),
        quic_port: 47808,
        tcp_port: 47810,
        nonce: vec![2],
        ts_ms: 1000,
    };
    let bytes = tagged_bytes(&b);
    inject_beacon(
        &mut store,
        &mut nonce,
        &mut rl,
        &bytes,
        "10.0.0.9".parse().unwrap(),
        None,
        1000,
    );
    assert!(store.get("cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d").is_some());
}

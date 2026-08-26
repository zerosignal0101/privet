
use privet_discovery::peer::PeerStore;
use privet_discovery::udp::{handle_incoming_datagram, NonceCache, RateLimiter};
use privet_protocol::{Beacon, Goodbye};
use std::net::IpAddr;
use std::str::FromStr;

fn make_beacon(ts_ms: u64) -> Vec<u8> {
    let b = Beacon {
        device_name: "test".into(),
        platform: "linux".into(),
        proto_version: 1,
        capabilities: vec![],
        device_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
        quic_port: 0,
        tcp_port: 0,
        nonce: b"unique_nonce_123".to_vec(),
        ts_ms,
    };
    privet_discovery::beacon::encode_beacon_tagged(&b).unwrap()
}

fn make_goodbye(device_fingerprint: &str) -> Vec<u8> {
    let g = Goodbye {
        device_fingerprint: device_fingerprint.into(),
    };
    privet_discovery::beacon::encode_goodbye_tagged(&g).unwrap()
}

#[test]
fn real_timestamped_beacon_is_accepted() {
    let now = 1_700_000_000_000u64;
    let bytes = make_beacon(now);
    let mut store = PeerStore::new();
    let mut nonce = NonceCache::new();
    let mut rl = RateLimiter::new();
    let src = IpAddr::from_str("10.0.0.1").unwrap();

    handle_incoming_datagram(&mut store, &bytes, src, None, now, &mut nonce, &mut rl);
    let peers = store.snapshot();
    assert!(
        !peers.is_empty(),
        "beacon with real now_ms should be accepted"
    );
}

#[test]
fn goodbye_reaches_handle_goodbye() {
    let fp = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let bytes = make_goodbye(fp);
    let mut store = PeerStore::new();
    store.handle_beacon(
        &privet_discovery::beacon::BeaconView {
            device_name: "alice".into(),
            platform: "linux".into(),
            proto_version: 1,
            capabilities: vec![],
            device_fingerprint: fp.into(),
            quic_port: 0,
            tcp_port: 0,
            nonce: b"nonce1".to_vec(),
            ts_ms: 1_700_000_000_000,
        },
        IpAddr::from_str("10.0.0.2").unwrap(),
        None,
        1_700_000_000_000,
    );
    let peers_before = store.snapshot();
    assert!(!peers_before.is_empty(), "peer should exist before goodbye");

    let mut nonce = NonceCache::new();
    let mut rl = RateLimiter::new();
    let src = IpAddr::from_str("10.0.0.2").unwrap();

    handle_incoming_datagram(
        &mut store,
        &bytes,
        src,
        None,
        1_700_000_000_000,
        &mut nonce,
        &mut rl,
    );

    let peers_after = store.snapshot();
    assert!(
        peers_after.is_empty()
            || peers_after
                .iter()
                .all(|p| p.state != privet_discovery::peer::PeerState::Live),
        "Goodbye should make peer absent or not-live"
    );
}

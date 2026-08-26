
use privet_discovery::beacon::BeaconView;
use privet_discovery::peer::{PeerEvent, PeerState, PeerStore, PeerStoreEvent};
use std::time::Duration;

fn view(fp: &str, ts: u64) -> BeaconView {
    BeaconView {
        device_name: "x".into(),
        platform: "l".into(),
        proto_version: 1,
        capabilities: vec![],
        device_fingerprint: fp.into(),
        quic_port: 47808,
        tcp_port: 47810,
        nonce: vec![1],
        ts_ms: ts,
    }
}

#[test]
fn sweep_live_to_stale_to_lost() {
    let mut s = PeerStore::new();
    let now = 1_000_000u64;
    // Absent --handle_beacon--> Seen --force--> Live
    s.handle_beacon(
        &view("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", now),
        "10.0.0.2".parse().unwrap(),
        None,
        now,
    );
    s.transition("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", PeerEvent::AddrResolved);
    s.transition("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", PeerEvent::ConnectOk);
    assert_eq!(s.get("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap().state, PeerState::Live);

    s.sweep(
        now + 200_000,
        Duration::from_secs(180),
        Duration::from_secs(300),
    );
    let ev = s.drain_events();
    assert!(ev.iter().any(
        |e| matches!(e, PeerStoreEvent::StateChanged(p, PeerState::Stale) if p == "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    ));
    assert_eq!(s.get("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap().state, PeerState::Stale);

    s.sweep(
        now + 310_000,
        Duration::from_secs(180),
        Duration::from_secs(300),
    );
    let ev = s.drain_events();
    assert!(ev
        .iter()
        .any(|e| matches!(e, PeerStoreEvent::Lost(p) if p == "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")));
    assert_eq!(s.get("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap().state, PeerState::Lost);
}

#[test]
fn sweep_skips_fresh_live_peer() {
    let mut s = PeerStore::new();
    let now = 1_000_000u64;
    s.handle_beacon(
        &view("cafebabe", now),
        "10.0.0.3".parse().unwrap(),
        None,
        now,
    );
    s.transition("cafebabe", PeerEvent::AddrResolved);
    s.transition("cafebabe", PeerEvent::ConnectOk);
    let _ = s.drain_events();
    s.sweep(
        now + 10_000,
        Duration::from_secs(180),
        Duration::from_secs(300),
    );
    assert!(s.drain_events().is_empty());
    assert_eq!(s.get("cafebabe").unwrap().state, PeerState::Live);
}

use privet_discovery::config::DiscoveryConfigPrivet;
use privet_discovery::engine::{DiscoveryEngine, LocalDeviceInfo};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

fn info() -> LocalDeviceInfo {
    LocalDeviceInfo {
        device_name: "me".into(),
        platform: "linux".into(),
        capabilities: vec!["quic".into()],
        device_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
        quic_port: 47808,
        tcp_port: 47810,
    }
}

#[test]
fn now_fn_is_injected() {
    let clock = Arc::new(AtomicU64::new(1_700_000_000_000));
    let c = clock.clone();
    let eng = DiscoveryEngine::with_now(
        info(),
        DiscoveryConfigPrivet::default(),
        Arc::new(move || c.load(Ordering::Relaxed)),
    );
    assert_eq!(eng.now_ms(), 1_700_000_000_000);
    clock.store(1_700_000_060_000, Ordering::Relaxed);
    assert_eq!(eng.now_ms(), 1_700_000_060_000);
}

// window expiry + broadcast targets
use privet_discovery::config::DiscoverabilityMode;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn should_announce_window_expiry() {
    let cfg = DiscoveryConfigPrivet {
        mode: DiscoverabilityMode::Window,
        window_secs: 600,
        ..Default::default()
    };
    let eng = DiscoveryEngine::new(info(), cfg);
    eng.set_start_ms_for_test(1_000_000);
    assert!(eng.should_announce(1_000_000));
    assert!(eng.should_announce(1_000_000 + 599_999));
    assert!(!eng.should_announce(1_000_000 + 600_000));
}

#[test]
fn should_announce_modes() {
    let eng = DiscoveryEngine::new(
        info(),
        DiscoveryConfigPrivet {
            mode: DiscoverabilityMode::Always,
            ..Default::default()
        },
    );
    assert!(eng.should_announce(0));

    let eng2 = DiscoveryEngine::new(
        info(),
        DiscoveryConfigPrivet {
            mode: DiscoverabilityMode::TrustedOnly,
            ..Default::default()
        },
    );
    assert!(!eng2.should_announce(0));
}

#[test]
fn broadcast_targets_includes_lan_fallback() {
    let eng = DiscoveryEngine::new(info(), DiscoveryConfigPrivet::default());
    let ts = eng.broadcast_targets();
    assert!(
        ts.iter()
            .any(|s| s.ip() == IpAddr::V4(Ipv4Addr::BROADCAST) && s.port() == 47809),
        "must always include 255.255.255.255:47809 fallback: {ts:?}"
    );
}

// Probe-response + message_tag
use privet_discovery::beacon::{decode_beacon_tagged, message_tag};
use privet_discovery::constants::PRIVET_DISCOVERY_PORT;
use privet_discovery::inject::CapturedSink;
use std::net::SocketAddr;

#[tokio::test]
async fn reply_to_probe_sends_beacon_to_prober_discovery_port() {
    let eng = DiscoveryEngine::new(info(), DiscoveryConfigPrivet::default());
    let sink = Arc::new(CapturedSink::new());
    eng.set_outgoing(sink.clone());
    let prober = "10.0.0.9:54321".parse::<SocketAddr>().unwrap();
    eng.reply_to_probe(prober).await;
    let cap = sink.captured();
    assert_eq!(cap.len(), 1);
    assert_eq!(
        cap[0].1,
        SocketAddr::new(prober.ip(), PRIVET_DISCOVERY_PORT)
    );
    assert_eq!(message_tag(&cap[0].0), Some(1)); // beacon tag
    let b = decode_beacon_tagged(&cap[0].0).unwrap();
    assert_eq!(b.device_fingerprint, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    assert_eq!(b.nonce.len(), 16);
}

#[test]
fn message_tag_reads_first_byte() {
    assert_eq!(message_tag(&[1, 2, 3]), Some(1));
    assert_eq!(message_tag(&[2]), Some(2));
    assert_eq!(message_tag(&[]), None);
}

// Probe on refresh + directed broadcast
use privet_discovery::beacon::decode_probe_tagged;

#[tokio::test]
async fn refresh_sends_probe_to_all_broadcast_targets() {
    let cfg = DiscoveryConfigPrivet {
        active_scan: true,
        ..Default::default()
    };
    let eng = DiscoveryEngine::new(info(), cfg);
    let sink = Arc::new(CapturedSink::new());
    eng.set_outgoing(sink.clone());
    eng.refresh().await.unwrap();
    let cap = sink.captured();
    assert!(!cap.is_empty(), "refresh must send >=1 Probe");
    assert!(
        cap.iter().all(|(d, _)| message_tag(d) == Some(2)),
        "all must be Probe (tag 2)"
    );
    let targets = eng.broadcast_targets();
    for t in &targets {
        assert!(
            cap.iter().any(|(_, dst)| dst == t),
            "Probe to {t:?} missing"
        );
    }
    let p = decode_probe_tagged(&cap[0].0).unwrap();
    assert!(!p.nonce.is_empty());
}

#[tokio::test]
async fn refresh_inactive_scan_sends_nothing() {
    let cfg = DiscoveryConfigPrivet {
        active_scan: false,
        ..Default::default()
    };
    let eng = DiscoveryEngine::new(info(), cfg);
    let sink = Arc::new(CapturedSink::new());
    eng.set_outgoing(sink.clone());
    eng.refresh().await.unwrap();
    assert!(sink.captured().is_empty());
}

// mDNS: on_mdns_resolved feeds store as beacon

#[test]
fn on_mdns_resolved_feeds_store_as_beacon() {
    let eng = DiscoveryEngine::new(info(), DiscoveryConfigPrivet::default());
    let v = BeaconView {
        device_name: "alice".into(),
        platform: "linux".into(),
        proto_version: 1,
        capabilities: vec![],
        device_fingerprint: "cafebabe".into(),
        quic_port: 47808,
        tcp_port: 47810,
        nonce: vec![],
        ts_ms: 0,
    };
    eng.on_mdns_resolved(v.clone(), vec!["10.0.0.5".parse().unwrap()], 1_000_000);
    let ev = eng.drain_events();
    assert!(ev
        .iter()
        .any(|e| matches!(e, PeerStoreEvent::Discovered(p) if p == "cafebabe")));
    assert_eq!(eng.peers()[0].state, PeerState::Seen);
    assert_eq!(
        eng.peers()[0].candidates[0].ip,
        "10.0.0.5".parse::<std::net::IpAddr>().unwrap()
    );
}

use privet_discovery::beacon::encode_beacon_tagged;
use privet_discovery::beacon::encode_probe_tagged;
use privet_discovery::netinfo::{enumerate_interfaces, probe_src_is_local_subnet};
use privet_protocol::{Beacon, Probe};

#[test]
fn probe_src_is_local_subnet_matches_local_and_rejects_foreign() {
    let ifaces = vec![
        (
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            24,
            None,
            "eth0".into(),
        ),
        (
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            16,
            None,
            "eth1".into(),
        ),
    ];
    assert!(probe_src_is_local_subnet(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
        &ifaces
    ));
    assert!(probe_src_is_local_subnet(
        IpAddr::V4(Ipv4Addr::new(10, 0, 255, 255)),
        &ifaces
    ));
    assert!(!probe_src_is_local_subnet(
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        &ifaces
    ));
    assert!(!probe_src_is_local_subnet(
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        &ifaces
    ));
    assert!(!probe_src_is_local_subnet(
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
        &[]
    ));
}

#[tokio::test]
async fn handle_inbound_replies_to_probe_in_always_mode() {
    let ifaces: Vec<_> = enumerate_interfaces()
        .into_iter()
        .filter(|(ip, prefix, _, _)| ip.is_ipv4() && *prefix < 32)
        .collect();
    if ifaces.is_empty() {
        return;
    }
    let (local_ip, _, _, _) = ifaces[0];
    let peer_ip = match local_ip {
        IpAddr::V4(v4) => {
            let mut oct = v4.octets();
            oct[3] = oct[3].wrapping_add(1);
            IpAddr::V4(Ipv4Addr::from(oct))
        }
        _ => local_ip,
    };
    // Host routes (/32, e.g. WSL2's 10.255.255.254 alias on lo) or an interface
    // assigned the subnet broadcast address yield no usable peer; skip then.
    if !probe_src_is_local_subnet(peer_ip, &ifaces) {
        return;
    }
    let eng = DiscoveryEngine::new(info(), DiscoveryConfigPrivet::default()); // Always
    let sink = Arc::new(CapturedSink::new());
    eng.set_outgoing(sink.clone());
    let probe = encode_probe_tagged(&Probe {
        nonce: vec![1, 2, 3],
        ts_ms: 0,
    })
    .unwrap();
    let src = SocketAddr::new(peer_ip, 54321);
    eng.handle_inbound(&probe, src, 1_000_000).await;
    let cap = sink.captured();
    assert_eq!(cap.len(), 1, "Always mode should reply with 1 beacon");
    assert_eq!(message_tag(&cap[0].0), Some(1)); // beacon
    assert_eq!(cap[0].1, SocketAddr::new(peer_ip, PRIVET_DISCOVERY_PORT));
}

#[tokio::test]
async fn handle_inbound_suppresses_reply_in_trusted_only() {
    let ifaces: Vec<_> = enumerate_interfaces()
        .into_iter()
        .filter(|(ip, _, _, _)| ip.is_ipv4())
        .collect();
    if ifaces.is_empty() {
        return;
    }
    let (local_ip, _, _, _) = ifaces[0];
    let peer_ip = match local_ip {
        IpAddr::V4(v4) => {
            let mut oct = v4.octets();
            oct[3] = oct[3].wrapping_add(1);
            IpAddr::V4(Ipv4Addr::from(oct))
        }
        _ => local_ip,
    };
    let cfg = DiscoveryConfigPrivet {
        mode: DiscoverabilityMode::TrustedOnly,
        ..Default::default()
    };
    let eng = DiscoveryEngine::new(info(), cfg);
    let sink = Arc::new(CapturedSink::new());
    eng.set_outgoing(sink.clone());
    let probe = encode_probe_tagged(&Probe {
        nonce: vec![4, 5, 6],
        ts_ms: 0,
    })
    .unwrap();
    eng.handle_inbound(&probe, SocketAddr::new(peer_ip, 54321), 1_000_000)
        .await;
    assert!(
        sink.captured().is_empty(),
        "TrustedOnly must not reply to Probe"
    );
}

#[tokio::test]
async fn handle_inbound_suppresses_reply_for_non_local_src() {
    let non_local = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let ifaces: Vec<_> = enumerate_interfaces()
        .into_iter()
        .filter(|(ip, _, _, _)| ip.is_ipv4())
        .collect();
    if probe_src_is_local_subnet(non_local, &ifaces) {
        return;
    }
    let eng = DiscoveryEngine::new(info(), DiscoveryConfigPrivet::default()); // Always
    let sink = Arc::new(CapturedSink::new());
    eng.set_outgoing(sink.clone());
    let probe = encode_probe_tagged(&Probe {
        nonce: vec![7, 8, 9],
        ts_ms: 0,
    })
    .unwrap();
    eng.handle_inbound(&probe, SocketAddr::new(non_local, 54321), 1_000_000)
        .await;
    assert!(
        sink.captured().is_empty(),
        "non-local src must not receive reply (amplification guard)"
    );
}

#[tokio::test]
async fn handle_inbound_does_not_reply_to_beacon() {
    let eng = DiscoveryEngine::new(info(), DiscoveryConfigPrivet::default());
    let sink = Arc::new(CapturedSink::new());
    eng.set_outgoing(sink.clone());
    let beacon = encode_beacon_tagged(&Beacon {
        device_name: "test".into(),
        platform: "l".into(),
        proto_version: 1,
        capabilities: vec![],
        device_fingerprint: "cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d".into(),
        quic_port: 0,
        tcp_port: 0,
        nonce: vec![10, 11, 12],
        ts_ms: 0,
    })
    .unwrap();
    eng.handle_inbound(
        &beacon,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 54321),
        0,
    )
    .await;
    assert!(sink.captured().is_empty(), "beacon must not trigger reply");
}

use privet_core::discovery::{build_local_device_info, map_peer_event};
use privet_core::{EngineConfig, EngineEvent};
use privet_crypto::identity::Identity;
use privet_discovery::peer::PeerStoreEvent;
use std::collections::HashMap;

#[test]
fn local_device_info_has_device_fingerprint_and_ports() {
    let id = Identity::generate().unwrap();
    let cfg = EngineConfig::default();
    let info = build_local_device_info(&id, &cfg, 47808, 47810, 5353);
    assert_eq!(info.quic_port, 47808);
    assert_eq!(info.tcp_port, 47810);
    assert!(!info.device_fingerprint.is_empty());
    assert!(info.capabilities.contains(&"quic".to_string()));
}

#[test]
fn discovered_and_lost_map_to_engine_events() {
    let empty = HashMap::new();
    let d = map_peer_event(
        PeerStoreEvent::Discovered("abc12345".into()),
        &empty,
        &empty,
    );
    assert!(matches!(d, Some(EngineEvent::DeviceDiscovered { .. })));
    let l = map_peer_event(PeerStoreEvent::Lost("abc12345".into()), &empty, &empty);
    assert!(matches!(l, Some(EngineEvent::DeviceLost { .. })));
}

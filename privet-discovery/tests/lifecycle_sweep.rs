
use privet_discovery::config::DiscoveryConfigPrivet;
use privet_discovery::engine::{DiscoveryEngine, LocalDeviceInfo};
use privet_discovery::peer::{PeerEvent, PeerState, PeerStoreEvent};
use std::sync::Arc;
use std::time::Duration;

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

/// A peer's fingerprint, distinct from the local device's own. The engine now
/// refuses to record a beacon whose fingerprint is its own, so the beacon fed
/// into the store here must be somebody else's.
const PEER_FP: &str = "cafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00dcafef00d";

#[tokio::test(start_paused = true)]
async fn sweep_task_promotes_stale_then_lost() {
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(1_000_000));
    let c = clock.clone();
    let eng = Arc::new(DiscoveryEngine::with_now(
        info(),
        DiscoveryConfigPrivet::default(),
        Arc::new(move || c.load(std::sync::atomic::Ordering::Relaxed)),
    ));
    let now = 1_000_000;
    let mut b = eng.make_beacon(now, vec![1, 2, 3, 4]);
    b.device_fingerprint = PEER_FP.to_string();
    let bytes = privet_discovery::beacon::encode_beacon_tagged(&b).unwrap();
    eng.inject_incoming(&bytes, "10.0.0.2".parse().unwrap(), None, now);
    eng.force_transition(PEER_FP, PeerEvent::AddrResolved);
    eng.force_transition(PEER_FP, PeerEvent::ConnectOk);
    assert_eq!(
        eng.peers()[0].state,
        PeerState::Live,
        "peer must be Live after setup"
    );
    let h = eng.clone().spawn_sweep_task();

    clock.store(1_000_000 + 200_000, std::sync::atomic::Ordering::Relaxed);
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::task::yield_now().await;
    assert!(
        eng.drain_events().iter().any(
            |e| matches!(e, PeerStoreEvent::StateChanged(p, PeerState::Stale) if p == PEER_FP)
        ),
        "peer must transition to Stale after 200s"
    );

    clock.store(1_000_000 + 310_000, std::sync::atomic::Ordering::Relaxed);
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::task::yield_now().await;
    assert!(
        eng.drain_events()
            .iter()
            .any(|e| matches!(e, PeerStoreEvent::Lost(p) if p == PEER_FP)),
        "peer must transition to Lost after 310s"
    );

    eng.cancel();
    tokio::task::yield_now().await;
    let _ = h.await;
}

#[tokio::test]
async fn self_beacon_is_never_recorded_as_a_peer() {
    let eng = DiscoveryEngine::with_now(
        info(),
        DiscoveryConfigPrivet::default(),
        Arc::new(|| 1_000_000u64),
    );
    let now = 1_000_000;
    // A beacon carrying our own fingerprint, from our own broadcast looping back
    // to the 0.0.0.0 listener, must not create a peer.
    let b = eng.make_beacon(now, vec![9, 9, 9, 9]);
    assert_eq!(
        b.device_fingerprint,
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    );
    let bytes = privet_discovery::beacon::encode_beacon_tagged(&b).unwrap();
    eng.inject_incoming(&bytes, "10.0.0.2".parse().unwrap(), None, now);
    assert!(
        eng.peers().is_empty(),
        "our own broadcast must not be recorded as a peer, got {:?}",
        eng.peers()
    );
}

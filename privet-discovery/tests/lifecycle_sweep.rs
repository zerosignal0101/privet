//! sweep 任务：30s 周期；Live -> Stale(180s) -> Lost(300s)。

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

#[tokio::test(start_paused = true)]
async fn sweep_task_promotes_stale_then_lost() {
    let clock = Arc::new(std::sync::atomic::AtomicU64::new(1_000_000));
    let c = clock.clone();
    let eng = Arc::new(DiscoveryEngine::with_now(
        info(),
        DiscoveryConfigPrivet::default(),
        Arc::new(move || c.load(std::sync::atomic::Ordering::Relaxed)),
    ));
    // 造一个 Live peer（构造 beacon 字节 inject）
    let now = 1_000_000;
    let b = eng.make_beacon(now, vec![1, 2, 3, 4]);
    let bytes = privet_discovery::beacon::encode_beacon_tagged(&b).unwrap();
    eng.inject_incoming(&bytes, "10.0.0.2".parse().unwrap(), None, now);
    eng.force_transition("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", PeerEvent::AddrResolved);
    eng.force_transition("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", PeerEvent::ConnectOk);
    assert_eq!(
        eng.peers()[0].state,
        PeerState::Live,
        "peer must be Live after setup"
    );
    let h = eng.clone().spawn_sweep_task();

    // +200s: 超 stale(180s) -> Stale
    clock.store(1_000_000 + 200_000, std::sync::atomic::Ordering::Relaxed);
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::task::yield_now().await;
    assert!(
        eng.drain_events().iter().any(
            |e| matches!(e, PeerStoreEvent::StateChanged(p, PeerState::Stale) if p == "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        ),
        "peer must transition to Stale after 200s"
    );

    // +310s: 超 lost(300s) -> Lost
    clock.store(1_000_000 + 310_000, std::sync::atomic::Ordering::Relaxed);
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::task::yield_now().await;
    assert!(
        eng.drain_events()
            .iter()
            .any(|e| matches!(e, PeerStoreEvent::Lost(p) if p == "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")),
        "peer must transition to Lost after 310s"
    );

    eng.cancel();
    tokio::task::yield_now().await;
    let _ = h.await;
}

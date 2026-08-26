
use privet_discovery::beacon::message_tag;
use privet_discovery::config::DiscoveryConfigPrivet;
use privet_discovery::engine::{DiscoveryEngine, LocalDeviceInfo};
use privet_discovery::inject::CapturedSink;
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
async fn stop_sends_goodbye_and_joins_tasks() {
    let eng = Arc::new(DiscoveryEngine::new(info(), DiscoveryConfigPrivet::default()));
    eng.set_start_ms_for_test(0);
    let sink = Arc::new(CapturedSink::new());
    eng.set_outgoing(sink.clone());
    let b = eng.clone().spawn_beacon_task();
    let s = eng.clone().spawn_sweep_task();

    eng.stop().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), b).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), s).await;
    let cap = sink.captured();
    assert!(
        cap.iter().any(|(d, _)| message_tag(d) == Some(3)),
        "Goodbye must be sent: {cap:?}"
    );
    let before = cap.len();
    tokio::time::advance(Duration::from_secs(120)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        sink.captured().len(),
        before,
        "no frames after stop (tasks joined)"
    );
}

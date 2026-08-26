//! beacon 任务时序：立即 + 每 60s。tokio::time::pause 推进虚拟时钟。

use privet_discovery::beacon::message_tag;
use privet_discovery::config::DiscoveryConfigPrivet;
use privet_discovery::constants::BEACON_INTERVAL;
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
async fn beacon_task_sends_immediate_then_periodic() {
    let eng = Arc::new(DiscoveryEngine::new(info(), DiscoveryConfigPrivet::default()));
    eng.set_start_ms_for_test(0);
    let sink = Arc::new(CapturedSink::new());
    eng.set_outgoing(sink.clone());
    let h = eng.clone().spawn_beacon_task();

    // 立即一帧：yield 让 spawn 任务有机会跑
    tokio::task::yield_now().await;
    assert!(!sink.captured().is_empty(), "immediate beacon");
    let n0 = sink.captured().len();
    assert!(sink
        .captured()
        .iter()
        .all(|(d, _)| message_tag(d) == Some(1)));

    // 推进 60s -> 第二帧
    tokio::time::advance(BEACON_INTERVAL).await;
    tokio::task::yield_now().await;
    assert!(sink.captured().len() > n0, "periodic beacon after 60s");

    eng.cancel(); // 停
    tokio::task::yield_now().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), h).await;
}

//! 周期 Probe 任务：注入时钟 + 捕获 sink，断言持续发 Probe。

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use privet_discovery::config::DiscoveryConfigPrivet;
use privet_discovery::engine::{DiscoveryEngine, LocalDeviceInfo};
use privet_discovery::udp::Outgoing;

/// 捕获对外发送的字节。
#[derive(Default, Clone)]
struct CapturedSink {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[async_trait]
impl Outgoing for CapturedSink {
    async fn send_to(&self, data: &[u8], _dst: SocketAddr) -> privet_discovery::Result<()> {
        self.sent.lock().unwrap().push(data.to_vec());
        Ok(())
    }
}

fn info() -> LocalDeviceInfo {
    LocalDeviceInfo {
        device_name: "test".into(),
        platform: "linux".into(),
        capabilities: vec!["quic".into()],
        device_fingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
        quic_port: 47808,
        tcp_port: 47810,
    }
}

#[tokio::test]
async fn spawn_probe_task_sends_repeatedly() {
    let cfg = DiscoveryConfigPrivet {
        probe_interval: std::time::Duration::from_millis(40),
        ..Default::default()
    };
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let now_fn = {
        let c = counter.clone();
        Arc::new(move || c.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
            as Arc<dyn Fn() -> u64 + Send + Sync>
    };
    let engine = Arc::new(DiscoveryEngine::with_now(info(), cfg, now_fn));
    let sink = CapturedSink::default();
    engine.set_outgoing(Arc::new(sink.clone()));
    let h = engine.clone().spawn_probe_task();
    tokio::time::sleep(std::time::Duration::from_millis(110)).await;
    engine.cancel();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), h).await;
    // 110ms / 40ms 间隔 -> 至少 2 帧 Probe（tag 首字节 = 2）。
    let probes = sink
        .sent
        .lock()
        .unwrap()
        .iter()
        .filter(|b| b.first() == Some(&2u8))
        .count();
    assert!(probes >= 2, "expected >=2 probes, got {probes}");
}

#[tokio::test]
async fn send_probe_to_unicasts_tagged_probe() {
    let engine = Arc::new(DiscoveryEngine::with_now(
        info(),
        DiscoveryConfigPrivet::default(),
        Arc::new(|| 1_700_000_000_000u64),
    ));
    let sink = CapturedSink::default();
    engine.set_outgoing(Arc::new(sink.clone()));
    let dst: SocketAddr = "10.0.0.7:47809".parse().unwrap();
    engine.send_probe_to(dst).await;
    let sent = sink.sent.lock().unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].first(), Some(&2u8), "probe tag = 2");
}

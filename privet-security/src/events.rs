//! 可观测事件：码/密钥/转录签名/exporter 绝不入事件。
use crate::PairingError;

#[derive(Debug, Clone)]
pub enum PairingEvent {
    /// 配对发起。
    PairingRequested { device_fingerprint: String },
    /// 配对结果（含原因码，不含码/密钥）。
    PairingResult {
        device_fingerprint: String,
        reason: Option<&'static str>,
    },
    /// 信任提交。
    TrustCommitted { device_fingerprint: String, state: String },
    /// 撤销。
    PeerRevoked { device_fingerprint: String },
    /// 密钥不符告警。
    KeyMismatchAlerted { device_fingerprint: String },
    /// ack 超时。
    AckTimeout { device_fingerprint: String },
}

impl PairingEvent {
    pub fn from_error(device_fingerprint: &str, e: &PairingError) -> Self {
        PairingEvent::PairingResult {
            device_fingerprint: device_fingerprint.to_string(),
            reason: Some(e.error_code()),
        }
    }
}

/// 事件 sink（core 注入真实总线；测试用 InMemory）。
pub trait PairingEventSink: Send + Sync {
    fn emit(&self, event: PairingEvent);
}

pub struct InMemoryEventSink {
    inner: std::sync::Mutex<Vec<PairingEvent>>,
}
impl InMemoryEventSink {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(Vec::new()),
        }
    }
    pub fn events(&self) -> Vec<PairingEvent> {
        self.inner.lock().unwrap().clone()
    }
}
impl Default for InMemoryEventSink {
    fn default() -> Self {
        Self::new()
    }
}
impl PairingEventSink for InMemoryEventSink {
    fn emit(&self, event: PairingEvent) {
        self.inner.lock().unwrap().push(event);
    }
}

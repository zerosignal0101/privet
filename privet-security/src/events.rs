use crate::PairingError;

#[derive(Debug, Clone)]
pub enum PairingEvent {
    PairingRequested { device_fingerprint: String },
    PairingResult {
        device_fingerprint: String,
        reason: Option<&'static str>,
    },
    TrustCommitted { device_fingerprint: String, state: String },
    PeerRevoked { device_fingerprint: String },
    KeyMismatchAlerted { device_fingerprint: String },
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

use privet_security::events::{PairingEvent, PairingEventSink};
use tokio::sync::broadcast;

use crate::EngineEvent;

pub struct CorePairingEventSink {
    tx: broadcast::Sender<EngineEvent>,
}

impl CorePairingEventSink {
    pub fn new(tx: broadcast::Sender<EngineEvent>) -> Self {
        Self { tx }
    }
}

impl PairingEventSink for CorePairingEventSink {
    fn emit(&self, event: PairingEvent) {
        let e = match event {
            PairingEvent::PairingRequested { device_fingerprint } => {
                tracing::info!(device_fingerprint = %device_fingerprint, "pairing requested");
                EngineEvent::PairingRequested { device_fingerprint }
            }
            PairingEvent::PairingResult { device_fingerprint, reason } => {
                let success = reason.is_none();
                tracing::info!(device_fingerprint = %device_fingerprint, success, "pairing result (reason only; no code/key)");
                EngineEvent::PairingResult {
                    device_fingerprint,
                    success,
                    error: reason.map(|s| s.to_string()),
                }
            }
            PairingEvent::TrustCommitted { device_fingerprint, .. } => {
                tracing::info!(device_fingerprint = %device_fingerprint, "trust committed (pairing complete)");
                EngineEvent::PairingResult {
                    device_fingerprint,
                    success: true,
                    error: None,
                }
            }
            PairingEvent::PeerRevoked { device_fingerprint } => {
                tracing::info!(device_fingerprint = %device_fingerprint, "peer revoked");
                EngineEvent::PairingResult {
                    device_fingerprint,
                    success: false,
                    error: Some("revoked".into()),
                }
            }
            PairingEvent::KeyMismatchAlerted { device_fingerprint } => {
                tracing::warn!(device_fingerprint = %device_fingerprint, "key mismatch alerted (MITM?)");
                EngineEvent::PairingResult {
                    device_fingerprint,
                    success: false,
                    error: Some("key_mismatch".into()),
                }
            }
            PairingEvent::AckTimeout { device_fingerprint } => {
                tracing::warn!(device_fingerprint = %device_fingerprint, "pairing ack timeout");
                EngineEvent::PairingResult {
                    device_fingerprint,
                    success: false,
                    error: Some("ack_timeout".into()),
                }
            }
        };
        let _ = self.tx.send(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::broadcast;

    #[tokio::test]
    async fn pairing_result_bridges_to_engine_event() {
        let (tx, mut rx) = broadcast::channel::<crate::EngineEvent>(16);
        let sink = CorePairingEventSink::new(tx);
        sink.emit(PairingEvent::PairingResult {
            device_fingerprint: "d".into(),
            reason: Some("code_mismatch"),
        });
        let got = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            got,
            crate::EngineEvent::PairingResult {
                device_fingerprint,
                success: false,
                ..
            } if device_fingerprint == "d"
        ));
    }
}

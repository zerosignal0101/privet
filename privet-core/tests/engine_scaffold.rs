use privet_core::{CoreError, EngineConfig, EngineEvent, Result};

#[test]
fn engine_config_default_compiles() {
    let cfg = EngineConfig::default();
    let _ = cfg.platform;
    let _ = cfg.device_name;
}

#[test]
fn core_error_maps_pairing_and_transfer() {
    let p = CoreError::from(privet_security::PairingError::CodeMismatch);
    let t = CoreError::from(privet_transfer::TransferError::Cancelled("x".into()));
    let d = CoreError::from(privet_transport::TransportError::Unavailable("x".into()));
    assert_eq!(p.error_code(), "pairing");
    assert_eq!(t.error_code(), "transfer");
    assert_eq!(d.error_code(), "transport");
}

#[test]
fn result_alias_resolves() {
    let r: Result<u32> = Err(privet_core::CoreError::Internal("x".into()));
    assert!(r.is_err());
    fn returns_result() -> Result<u32> {
        Ok(42)
    }
    assert_eq!(returns_result().unwrap_or(0), 42);
}

#[tokio::test]
async fn engine_event_broadcast_roundtrip() {
    let (tx, mut rx) = tokio::sync::broadcast::channel::<EngineEvent>(16);
    tx.send(EngineEvent::TransferCompleted {
        transfer_id: "t1".into(),
    })
    .unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        got,
        EngineEvent::TransferCompleted { transfer_id } if transfer_id == "t1"
    ));
}

#[test]
fn engine_event_variants_cover_spec() {
    let _ = EngineEvent::DeviceDiscovered {
        device_fingerprint: "d".into(),
        device_name: "n".into(),
    };
    let _ = EngineEvent::DeviceLost {
        device_fingerprint: "d".into(),
    };
    let _ = EngineEvent::TransferReconnecting {
        transfer_id: "t".into(),
        attempt: 1,
        backoff_ms: 1000,
    };
    let _ = EngineEvent::TransferResumed {
        transfer_id: "t".into(),
    };
    let _ = EngineEvent::TransferPaused {
        transfer_id: "t".into(),
        reason: privet_transfer::PausedReason::User,
    };
    let _ = EngineEvent::TransferFailed {
        transfer_id: "t".into(),
        error_code: "transport".into(),
        retryable: true,
        part_kept: true,
    };
}

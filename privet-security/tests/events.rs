use privet_security::events::*;

#[test]
fn event_carries_no_code_or_keys() {
    let e = PairingEvent::PairingRequested {
        device_fingerprint: "d1".into(),
    };
    let s = format!("{e:?}");
    assert!(
        !s.contains("code") && !s.contains("spki") && !s.contains("sig") && !s.contains("exporter")
    );

    let e2 = PairingEvent::PairingResult {
        device_fingerprint: "d1".into(),
        reason: Some("ack_timeout"),
    };
    let s2 = format!("{e2:?}");
    assert!(!s2.contains("123456"));
}

#[test]
fn in_memory_sink_records_sequence() {
    let sink = InMemoryEventSink::new();
    sink.emit(PairingEvent::PairingRequested {
        device_fingerprint: "d1".into(),
    });
    sink.emit(PairingEvent::PairingResult {
        device_fingerprint: "d1".into(),
        reason: Some("code_mismatch"),
    });
    let evs = sink.events();
    assert_eq!(evs.len(), 2);
    assert!(matches!(evs[0], PairingEvent::PairingRequested { .. }));
}

#[test]
fn trust_committed_and_revoked_events() {
    let sink = InMemoryEventSink::new();
    sink.emit(PairingEvent::TrustCommitted {
        device_fingerprint: "d1".into(),
        state: "Trusted".into(),
    });
    sink.emit(PairingEvent::PeerRevoked {
        device_fingerprint: "d1".into(),
    });
    assert_eq!(sink.events().len(), 2);
}

#[test]
fn from_error_maps_ack_timeout() {
    let e = PairingEvent::from_error("d1", &privet_security::PairingError::AckTimeout);
    match e {
        PairingEvent::PairingResult { device_fingerprint, reason } => {
            assert_eq!(device_fingerprint, "d1");
            assert_eq!(reason, Some("ack_timeout"));
        }
        _ => panic!("expected PairingResult"),
    }
}

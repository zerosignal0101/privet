use privet_crypto::identity::Identity;
use privet_security::cert::*;
use privet_security::trust::*;

fn id() -> Identity {
    Identity::generate().unwrap()
}

#[test]
fn extract_spki_from_self_signed_cert_matches_identity() {
    let id = id();
    let spki = extract_spki(id.cert_der()).unwrap();
    assert_eq!(spki, id.spki_der());
}

#[test]
fn pin_unknown_when_not_in_store() {
    let store = InMemoryTrustStore::new();
    let d = pin(&[1, 2, 3], "ghost", &store).unwrap();
    assert!(matches!(d, PinDecision::Unknown));
}

#[test]
fn pin_trusted_when_spki_matches() {
    let store = InMemoryTrustStore::new();
    store
        .commit_peer(PeerTrust {
            device_fingerprint: "d1".into(),
            peer_spki: vec![1, 2, 3],
            peer_device_name: "p".into(),
            share_with_peers: false,
            first_paired_ts: 1,
            last_seen_ts: 1,
        })
        .unwrap();
    let d = pin(&[1, 2, 3], "d1", &store).unwrap();
    assert!(matches!(d, PinDecision::Trusted));
}

#[test]
fn pin_key_mismatch_when_spki_differs_fail_closed() {
    let store = InMemoryTrustStore::new();
    store
        .commit_peer(PeerTrust {
            device_fingerprint: "d1".into(),
            peer_spki: vec![1, 2, 3],
            peer_device_name: "p".into(),
            share_with_peers: false,
            first_paired_ts: 1,
            last_seen_ts: 1,
        })
        .unwrap();
    let d = pin(&[9, 9, 9], "d1", &store).unwrap();
    assert!(matches!(d, PinDecision::KeyMismatch { .. }));
    let r = store.get("d1").unwrap().unwrap();
    assert_eq!(r.trust_state, TrustState::Trusted);
}

#[test]
fn pin_revoked() {
    let store = InMemoryTrustStore::new();
    store
        .commit_peer(PeerTrust {
            device_fingerprint: "d1".into(),
            peer_spki: vec![1, 2, 3],
            peer_device_name: "p".into(),
            share_with_peers: false,
            first_paired_ts: 1,
            last_seen_ts: 1,
        })
        .unwrap();
    store.revoke("d1", "user", 999).unwrap();
    let d = pin(&[1, 2, 3], "d1", &store).unwrap();
    assert!(matches!(d, PinDecision::Revoked));
}

#[test]
fn conn_auth_decision_maps_per_spec_8() {
    use ConnAuthAction::*;
    assert!(matches!(
        conn_auth_decision(PinDecision::Trusted),
        AcceptCodeless
    ));
    assert!(matches!(
        conn_auth_decision(PinDecision::Unknown),
        TriggerPairing
    ));
    assert!(matches!(conn_auth_decision(PinDecision::Revoked), Reject));
    assert!(matches!(
        conn_auth_decision(PinDecision::KeyMismatch {
            stored_spki: vec![]
        }),
        FailClosedAlert
    ));
}

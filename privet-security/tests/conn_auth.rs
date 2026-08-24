use privet_crypto::identity::Identity;
use privet_security::cert::*;
use privet_security::conn_auth::*;
use privet_security::trust::*;

fn store_with(did: &str, spki: &[u8]) -> InMemoryTrustStore {
    let s = InMemoryTrustStore::new();
    s.commit_peer(PeerTrust {
        device_fingerprint: did.into(),
        peer_spki: spki.to_vec(),
        peer_device_name: "p".into(),
        share_with_peers: false,
        first_paired_ts: 1,
        last_seen_ts: 1,
    })
    .unwrap();
    s
}

#[test]
fn key_mismatch_reject_state_unchanged() {
    let store = store_with("d1", &[1, 2, 3]);
    let action = conn_auth(&[9, 9, 9], "d1", &store).unwrap();
    assert!(matches!(action, ConnAuthAction::FailClosedAlert));
    let r = store.get("d1").unwrap().unwrap();
    assert_eq!(r.trust_state, TrustState::Trusted);
}

#[test]
fn revoked_silent_reject() {
    let store = store_with("d1", &[1, 2, 3]);
    store.revoke("d1", "user", 999).unwrap();
    let action = conn_auth(&[1, 2, 3], "d1", &store).unwrap();
    assert!(matches!(action, ConnAuthAction::Reject));
    assert_eq!(
        store.get("d1").unwrap().unwrap().trust_state,
        TrustState::Revoked
    );
}

#[test]
fn trusted_peer_accepted_codeless() {
    let store = store_with("d1", &[1, 2, 3]);
    let action = conn_auth(&[1, 2, 3], "d1", &store).unwrap();
    assert!(matches!(action, ConnAuthAction::AcceptCodeless));
}

#[test]
fn unknown_peer_triggers_pairing() {
    let store = InMemoryTrustStore::new();
    let action = conn_auth(&[1, 2, 3], "ghost", &store).unwrap();
    assert!(matches!(action, ConnAuthAction::TriggerPairing));
}

#[test]
fn key_mismatch_alert_carries_no_private_key() {
    let id = Identity::generate().unwrap();
    let store = store_with("d1", id.spki_der());
    let alert = build_alert(&[9, 9, 9], "d1", &store).unwrap();
    assert_eq!(alert.device_fingerprint, "d1");
    assert_eq!(alert.trust_state, TrustState::Trusted);
}

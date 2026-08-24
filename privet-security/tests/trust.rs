use privet_security::trust::*;

fn pt(fingerprint: &str) -> PeerTrust {
    PeerTrust {
        device_fingerprint: fingerprint.into(),
        peer_spki: vec![1, 2, 3],
        peer_device_name: "p".into(),
        share_with_peers: false,
        first_paired_ts: 100,
        last_seen_ts: 100,
    }
}

#[test]
fn commit_then_get_returns_trusted() {
    let s = InMemoryTrustStore::new();
    assert!(s.get("d1").unwrap().is_none());
    s.commit_peer(pt("d1")).unwrap();
    let r = s.get("d1").unwrap().unwrap();
    assert_eq!(r.trust_state, TrustState::Trusted);
    assert_eq!(r.peer_spki, vec![1, 2, 3]);
}

#[test]
fn commit_peer_upsert_overwrites_on_repair() {
    let s = InMemoryTrustStore::new();
    s.commit_peer(pt("d1")).unwrap();
    let mut p2 = pt("d1");
    p2.peer_spki = vec![9, 9, 9];
    p2.peer_device_name = "p2".into();
    s.commit_peer(p2).unwrap();
    let r = s.get("d1").unwrap().unwrap();
    assert_eq!(r.peer_spki, vec![9, 9, 9]);
    assert_eq!(r.peer_device_name, "p2");
    assert_eq!(r.trust_state, TrustState::Trusted);
}

#[test]
fn revoke_flips_to_revoked_and_back_on_repair() {
    let s = InMemoryTrustStore::new();
    s.commit_peer(pt("d1")).unwrap();
    s.revoke("d1", "user", 999).unwrap();
    let r = s.get("d1").unwrap().unwrap();
    assert_eq!(r.trust_state, TrustState::Revoked);
    assert_eq!(r.revoked_ts, Some(999));
    s.commit_peer(pt("d1")).unwrap();
    assert_eq!(
        s.get("d1").unwrap().unwrap().trust_state,
        TrustState::Trusted
    );
}

#[test]
fn refresh_seen_updates_last_seen_and_name() {
    let s = InMemoryTrustStore::new();
    s.commit_peer(pt("d1")).unwrap();
    s.refresh_seen("d1", "renamed", 200).unwrap();
    let r = s.get("d1").unwrap().unwrap();
    assert_eq!(r.peer_device_name, "renamed");
    assert_eq!(r.last_seen_ts, 200);
}

#[test]
fn forget_removes_entry() {
    let s = InMemoryTrustStore::new();
    s.commit_peer(pt("d1")).unwrap();
    s.forget("d1").unwrap();
    assert!(s.get("d1").unwrap().is_none());
}

#[test]
fn trust_state_db_str_roundtrip() {
    assert_eq!(TrustState::from_db_str("Trusted"), TrustState::Trusted);
    assert_eq!(TrustState::from_db_str("Revoked"), TrustState::Revoked);
    assert_eq!(TrustState::from_db_str("???"), TrustState::Unknown);
    assert_eq!(TrustState::Trusted.to_db_str(), "Trusted");
    assert_eq!(TrustState::Revoked.to_db_str(), "Revoked");
}

#[test]
fn revoke_unknown_is_noop_ok() {
    let s = InMemoryTrustStore::new();
    assert!(s.revoke("ghost", "x", 1).is_ok());
}

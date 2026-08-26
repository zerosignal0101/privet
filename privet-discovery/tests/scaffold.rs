#[test]
fn constants_visible() {
    assert_eq!(privet_discovery::PRIVET_DISCOVERY_PORT, 47809);
    assert_eq!(
        privet_discovery::BEACON_INTERVAL,
        std::time::Duration::from_secs(60)
    );
    assert_eq!(
        privet_discovery::PEER_STALE_TIMEOUT,
        std::time::Duration::from_secs(180)
    );
    assert_eq!(
        privet_discovery::PEER_LOST_TIMEOUT,
        std::time::Duration::from_secs(300)
    );
    assert_eq!(privet_discovery::EVICT_FAILS, 5);
}

#[test]
fn error_constructs() {
    let e = privet_discovery::DiscoveryError::BeaconInvalid("bad".into());
    assert!(format!("{e}").contains("bad"));
}

use privet_core::{Engine, EngineConfig};
use tempfile::TempDir;

fn engine() -> (Engine, TempDir) {
    let dir = TempDir::new().unwrap();
    let cfg = EngineConfig {
        device_name: "alice".into(),
        db_path: dir.path().join("p.db"),
        save_dir: dir.path().to_path_buf(),
        identity_path: Some(dir.path().join("id.bin")),
        ..Default::default()
    };
    (Engine::new(cfg), dir)
}

#[test]
fn identity_info_has_name_and_device_fingerprint() {
    let (e, _d) = engine();
    let info = e.identity_info();
    assert_eq!(info.name, "alice");
    assert!(!info.device_fingerprint.is_empty());
}

#[test]
fn list_trusted_empty_then_seed() {
    let (e, dir) = engine();
    assert!(e.list_trusted().unwrap().is_empty());
    let conn = privet_storage::migration::open_and_migrate(dir.path().join("p.db")).unwrap();
    privet_storage::trust::insert_paired(
        &conn,
        &privet_storage::trust::PeerTrust {
            device_fingerprint: "dev1",
            peer_spki: &[1],
            peer_device_name: "bob",
            share_with_peers: false,
            first_paired_ts: 1,
            last_seen_ts: 1,
        },
        &privet_storage::trust::PeerAddress {
            subnet_cidr: "10.0.0.0/24",
            gateway_ip: None,
            addr: "10.0.0.5",
            quic_port: 47808,
            tcp_port: 47810,
            source: "self",
            last_seen_ts: 1,
        },
    )
    .unwrap();
    drop(conn);
    let all = e.list_trusted().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].device_fingerprint, "dev1");
    assert_eq!(all[0].peer_device_name, "bob");
}

#[test]
fn history_empty_by_default() {
    let (e, _d) = engine();
    let rows = e.history(None, 100).unwrap();
    assert!(rows.is_empty());
}

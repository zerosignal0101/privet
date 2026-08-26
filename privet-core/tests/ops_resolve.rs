//! E4: Engine::resolve_peer + prepare_paths（对端解析 + 多路径准备）。
use tempfile::TempDir;

use privet_core::ops::{prepare_paths, PeerTarget};
use privet_core::{Engine, EngineConfig};

fn engine() -> (Engine, TempDir) {
    let dir = TempDir::new().unwrap();
    let cfg = EngineConfig {
        db_path: dir.path().join("p.db"),
        save_dir: dir.path().to_path_buf(),
        identity_path: Some(dir.path().join("id.bin")),
        ..Default::default()
    };
    (Engine::new(cfg), dir)
}

#[test]
fn resolve_by_addr_uses_addr_directly() {
    let (e, _d) = engine();
    let addr: std::net::SocketAddr = "127.0.0.1:47808".parse().unwrap();
    let pa = e.resolve_peer(&PeerTarget::ByAddr(addr), None).unwrap();
    assert_eq!(pa.addr, addr);
    assert!(pa.device_fingerprint.is_none());
}

#[test]
fn resolve_by_device_fingerprint_uses_recent_address() {
    let (e, dir) = engine();
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
            subnet_cidr: "127.0.0.0/8",
            gateway_ip: None,
            addr: "127.0.0.9",
            quic_port: 47808,
            tcp_port: 47810,
            source: "self",
            last_seen_ts: 1,
        },
    )
    .unwrap();
    privet_storage::addresses::inc_success(&conn, "dev1", "127.0.0.0/8", "127.0.0.9", 2).unwrap();
    drop(conn);
    let pa = e
        .resolve_peer(&PeerTarget::ByDeviceFingerprint("dev1".into()), None)
        .unwrap();
    assert_eq!(pa.device_fingerprint.as_deref(), Some("dev1"));
    assert_eq!(pa.peer_name.as_deref(), Some("bob"));
    assert!(pa.addr.ip().to_string() == "127.0.0.9");
    assert_eq!(pa.addr.port(), 47808);
}

#[test]
fn resolve_unknown_device_fingerprint_errors_not_paired() {
    let (e, _d) = engine();
    let err = e
        .resolve_peer(&PeerTarget::ByDeviceFingerprint("ghost".into()), None)
        .unwrap_err();
    assert!(matches!(err, privet_core::CoreError::NotPaired(_)));
}

#[test]
fn resolve_via_overrides_ip_keeps_ports() {
    let (e, dir) = engine();
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
            subnet_cidr: "127.0.0.0/8",
            gateway_ip: None,
            addr: "127.0.0.9",
            quic_port: 47808,
            tcp_port: 47810,
            source: "self",
            last_seen_ts: 1,
        },
    )
    .unwrap();
    privet_storage::addresses::inc_success(&conn, "dev1", "127.0.0.0/8", "127.0.0.9", 2).unwrap();
    drop(conn);
    let via: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let pa = e
        .resolve_peer(&PeerTarget::ByDeviceFingerprint("dev1".into()), Some(via))
        .unwrap();
    assert_eq!(pa.addr.ip(), via);
    assert_eq!(pa.addr.port(), 47808);
}

#[test]
fn prepare_paths_single_file_and_dir() {
    let dir = TempDir::new().unwrap();
    let f = dir.path().join("a.txt");
    std::fs::write(&f, b"hello").unwrap();
    let sub = dir.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    std::fs::write(sub.join("b.txt"), b"world").unwrap();

    let cfg = privet_transfer::TransferEngineConfig::default();
    let ps = prepare_paths(
        std::slice::from_ref(&f),
        None,
        cfg.default_chunk_size,
        cfg.segment_max_chunks,
    )
    .unwrap();
    assert_eq!(ps.files.len(), 1);
    assert_eq!(ps.files[0].relative_path, "a.txt");

    let ps2 = prepare_paths(
        &[sub],
        Some("sub"),
        cfg.default_chunk_size,
        cfg.segment_max_chunks,
    )
    .unwrap();
    assert_eq!(ps2.files.len(), 1);
    assert_eq!(ps2.files[0].relative_path, "b.txt");
    assert_eq!(ps2.root_name.as_deref(), Some("sub"));
}

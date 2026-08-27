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

fn seed_completed_send(e: &Engine) {
    let conn = e.db_conn().unwrap();
    privet_storage::history::insert_history(
        &conn,
        &privet_storage::history::NewTransfer {
            transfer_id: "t-send",
            direction: privet_storage::history::TransferDirection::Send,
            peer_device_fingerprint: None,
            peer_name: Some("peer"),
            root_name: Some("docs"),
            file_count: 1,
            total_bytes: 10,
            status: privet_storage::history::TransferStatus::Completed,
            started_ts: 1,
            save_dir: None,
            send_intent: "{\"paths\":[\"/home/u/docs\"],\"chunk_size\":1048576,\"segment_max_chunks\":1024}",
        },
    )
    .unwrap();
    privet_storage::history::complete_history(
        &conn,
        "t-send",
        &[privet_storage::history::FileRow {
            file_id: "f1",
            relative_path: "a.txt",
            size: 10,
            hash_type: "blake3".into(),
            hash_value: Some("h"),
            status: "completed",
            source_path: Some("/home/u/docs/a.txt"),
        }],
        2,
    )
    .unwrap();
}

#[test]
fn history_detail_returns_none_for_unknown_transfer() {
    let (e, _d) = engine();
    assert!(e.history_detail("missing").unwrap().is_none());
}

#[test]
fn history_detail_returns_seeded_files_and_source_path() {
    let (e, _d) = engine();
    seed_completed_send(&e);
    let detail = e.history_detail("t-send").unwrap().unwrap();
    assert_eq!(detail.direction, "send");
    assert_eq!(detail.files.len(), 1);
    assert_eq!(detail.files[0].relative_path, "a.txt");
    assert_eq!(detail.files[0].source_path.as_deref(), Some("/home/u/docs/a.txt"));
}

#[test]
fn delete_history_removes_the_entry() {
    let (e, _d) = engine();
    seed_completed_send(&e);
    e.delete_history("t-send").unwrap();
    assert!(e.history_detail("t-send").unwrap().is_none());
}

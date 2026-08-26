//! 续传意图错误路径：resume_send 各校验分支。
//! 注：跨连接续传 e2e 见 reconnect_e2e.rs::drop_mid_transfer_then_resume。
use privet_core::{Engine, EngineConfig};
use tempfile::TempDir;

fn test_engine() -> (Engine, TempDir) {
    let dir = TempDir::new().unwrap();
    let cfg = EngineConfig {
        db_path: dir.path().join("test.db"),
        save_dir: dir.path().join("save"),
        device_name: "test".into(),
        platform: "linux".into(),
        ..Default::default()
    };
    (Engine::new(cfg), dir)
}

fn insert_partial_send_row(
    engine: &Engine,
    tid: &str,
    peer_device_fingerprint: Option<&str>,
) {
    let db = engine.db_conn().unwrap();
    if let Some(pid) = peer_device_fingerprint {
        let _ = db.execute(
            "INSERT OR IGNORE INTO trust_store(device_fingerprint,peer_spki,peer_device_name,first_paired_ts,last_seen_ts) VALUES(?1,x'00','n',1,1)",
            [pid],
        );
    }
    privet_storage::history::insert_history(
        &db,
        &privet_storage::history::NewTransfer {
            transfer_id: tid,
            direction: privet_storage::history::TransferDirection::Send,
            peer_device_fingerprint,
            peer_name: Some("peer"),
            root_name: None,
            file_count: 1,
            total_bytes: 100,
            status: privet_storage::history::TransferStatus::Partial,
            started_ts: 1,
            save_dir: None,
            send_intent: "{}".into()
        },
    )
    .unwrap();
}

#[tokio::test]
async fn resume_send_not_found_returns_internal() {
    let (engine, _dir) = test_engine();
    match engine.resume_send("ghost_tid").await {
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("not found"), "expected not found, got: {msg}");
        }
        Ok(_) => panic!("expected error for ghost tid"),
    }
}

#[tokio::test]
async fn resume_send_wrong_direction_error() {
    let (engine, _dir) = test_engine();
    let tid = "t-dir";
    {
        let db = engine.db_conn().unwrap();
        privet_storage::history::insert_history(
            &db,
            &privet_storage::history::NewTransfer {
                transfer_id: tid,
                direction: privet_storage::history::TransferDirection::Receive,
                peer_device_fingerprint: None,
                peer_name: Some("p"),
                root_name: None,
                file_count: 1,
                total_bytes: 100,
                status: privet_storage::history::TransferStatus::Partial,
                started_ts: 1,
                save_dir: Some("/tmp/s"),
                send_intent: "{}".into()
            },
        )
        .unwrap();
    }
    match engine.resume_send(tid).await {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("not a send"),
                "expected direction error, got: {msg}"
            );
        }
        Ok(_) => panic!("expected error for wrong direction"),
    }
}

#[tokio::test]
async fn resume_send_not_partial_error() {
    let (engine, _dir) = test_engine();
    let tid = "t-partial";
    {
        let db = engine.db_conn().unwrap();
        privet_storage::history::insert_history(
            &db,
            &privet_storage::history::NewTransfer {
                transfer_id: tid,
                direction: privet_storage::history::TransferDirection::Send,
                peer_device_fingerprint: None,
                peer_name: Some("p"),
                root_name: None,
                file_count: 1,
                total_bytes: 100,
                status: privet_storage::history::TransferStatus::Completed,
                started_ts: 1,
                save_dir: None,
                send_intent: "{}".into()
            },
        )
        .unwrap();
    }
    match engine.resume_send(tid).await {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("not resumable"),
                "expected not resumable, got: {msg}"
            );
        }
        Ok(_) => panic!("expected error for completed status"),
    }
}

#[tokio::test]
async fn resume_send_no_intent_error() {
    let (engine, _dir) = test_engine();
    let tid = "t-intent";
    insert_partial_send_row(&engine, tid, None);
    match engine.resume_send(tid).await {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("no send intent"),
                "expected no intent, got: {msg}"
            );
        }
        Ok(_) => panic!("expected error for missing intent"),
    }
}

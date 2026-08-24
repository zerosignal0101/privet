//! storage-layer path guard defense-in-depth.
//! insert_history, complete_history, and sidecar path builders reject traversal paths.

use privet_storage::db::open_in_memory;
use privet_storage::error::StorageError;
use privet_storage::history::{
    insert_history, FileRow, NewTransfer, TransferDirection, TransferStatus,
};
use privet_storage::migration::{run_migrations, MIGRATIONS};
use privet_storage::sidecar;

fn db() -> rusqlite::Connection {
    let conn = open_in_memory().unwrap();
    run_migrations(&conn, MIGRATIONS).unwrap();
    conn
}

#[test]
fn insert_history_rejects_bad_root_name() {
    let conn = db();
    let err = insert_history(
        &conn,
        &NewTransfer {
            transfer_id: "t1",
            direction: TransferDirection::Receive,
            peer_device_fingerprint: None,
            peer_name: None,
            root_name: Some("../evil"),
            file_count: 0,
            total_bytes: 0,
            status: TransferStatus::Partial,
            started_ts: 1,
            save_dir: Some("/tmp/s"),
            send_intent: "{}".into()
        },
    )
    .unwrap_err();
    assert!(
        matches!(err, StorageError::Path(_)),
        "expected Path error, got {err:?}"
    );
}

#[test]
fn complete_history_rejects_bad_relative_path() {
    let conn = db();
    // valid insert first
    insert_history(
        &conn,
        &NewTransfer {
            transfer_id: "t1",
            direction: TransferDirection::Receive,
            peer_device_fingerprint: None,
            peer_name: None,
            root_name: None,
            file_count: 1,
            total_bytes: 10,
            status: TransferStatus::Partial,
            started_ts: 1,
            save_dir: Some("/tmp/s"),
            send_intent: "{}".into()
        },
    )
    .unwrap();
    let err = privet_storage::history::complete_history(
        &conn,
        "t1",
        &[FileRow {
            file_id: "f1",
            relative_path: "../../evil",
            size: 10,
            hash_type: "blake3".into(),
            hash_value: None,
            status: "completed",
        }],
        999,
    )
    .unwrap_err();
    assert!(
        matches!(err, StorageError::Path(_)),
        "expected Path error for traversal relative_path, got {err:?}"
    );
}

#[test]
fn sidecar_path_fns_reject_traversal() {
    let dir = tempfile::tempdir().unwrap();
    let err = sidecar::part_meta_path(dir.path(), "t1", "../../evil").unwrap_err();
    assert!(matches!(err, StorageError::Path(_)));
    let err = sidecar::part_path(dir.path(), "t1", "../../evil").unwrap_err();
    assert!(matches!(err, StorageError::Path(_)));
}

#[test]
fn sidecar_path_fns_accept_safe() {
    let dir = tempfile::tempdir().unwrap();
    let p = sidecar::part_meta_path(dir.path(), "t1", "a/b.txt").unwrap();
    assert!(p.to_string_lossy().contains("a/b.txt.part.meta"));
    let p = sidecar::part_path(dir.path(), "t1", "a/b.txt").unwrap();
    assert!(p.to_string_lossy().contains("a/b.txt.part"));
}

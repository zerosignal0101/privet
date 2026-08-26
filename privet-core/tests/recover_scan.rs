//! recover_partial_transfers only scans staging dir, not user dirs.

fn create_db(conn: &rusqlite::Connection) {
    // Manually create schema for the test
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS transfer_history (
            transfer_id TEXT PRIMARY KEY,
            direction TEXT NOT NULL,
            file_count INTEGER NOT NULL,
            total_bytes INTEGER NOT NULL,
            status TEXT NOT NULL,
            started_ts INTEGER NOT NULL,
            save_dir TEXT
        )",
    )
    .unwrap();
}

#[test]
fn recover_partial_scans_only_staging_dir() {
    let save = tempfile::tempdir().unwrap();
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    create_db(&conn);

    // Create a legitimate empty user directory
    std::fs::create_dir(save.path().join("user_empty_dir")).unwrap();

    // Create the staging directory with an empty transfer dir
    let staging = save.path().join(".privet").join("old_transfer");
    std::fs::create_dir_all(&staging).unwrap();

    // Run recovery
    privet_core::transfer::recover_partial_transfers(save.path(), &conn).unwrap();

    // The user-created dir must survive
    assert!(
        save.path().join("user_empty_dir").exists(),
        "empty user dir must survive recovery scan"
    );
}

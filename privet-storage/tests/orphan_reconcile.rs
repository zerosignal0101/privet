
use privet_storage::db::open_in_memory;
use privet_storage::migration::{run_migrations, MIGRATIONS};
use privet_storage::staging::orphan_reconcile;

fn create_db() -> rusqlite::Connection {
    let conn = open_in_memory().unwrap();
    run_migrations(&conn, MIGRATIONS).unwrap();
    conn
}

#[test]
fn partial_send_and_other_save_dir_not_marked_failed() {
    let conn = create_db();
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

    // a partial SEND (save_dir=NULL) — should NOT be touched
    conn.execute(
        "INSERT INTO transfer_history(transfer_id,direction,file_count,total_bytes,status,started_ts,save_dir,send_intent)
         VALUES('t_send','send',1,10,'partial',1,NULL,'{}')",
        [],
    )
    .unwrap();

    // a partial RECEIVE in dir_b — should NOT be touched when reconciling dir_a
    conn.execute(
        "INSERT INTO transfer_history(transfer_id,direction,file_count,total_bytes,status,started_ts,save_dir,send_intent)
         VALUES('t_recv_b','receive',1,10,'partial',1,?1,'{}')",
        [dir_b.path().to_str().unwrap()],
    )
    .unwrap();

    // reconcile dir_a — neither row belongs to dir_a
    orphan_reconcile(dir_a.path(), &conn).unwrap();

    let s: String = conn
        .query_row(
            "SELECT status FROM transfer_history WHERE transfer_id='t_send'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(s, "partial", "send must stay partial");

    let s: String = conn
        .query_row(
            "SELECT status FROM transfer_history WHERE transfer_id='t_recv_b'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(s, "partial", "other save_dir receive must stay partial");
}

#[test]
fn partial_receive_in_save_dir_no_files_marked_failed() {
    // a RECEIVE with matching save_dir but no staging files IS reconciled.
    let conn = create_db();
    let dir_a = tempfile::tempdir().unwrap();

    conn.execute(
        "INSERT INTO transfer_history(transfer_id,direction,file_count,total_bytes,status,started_ts,save_dir,send_intent)
         VALUES('t_recv_a','receive',1,10,'partial',1,?1,'{}')",
        [dir_a.path().to_str().unwrap()],
    )
    .unwrap();

    orphan_reconcile(dir_a.path(), &conn).unwrap();

    let s: String = conn
        .query_row(
            "SELECT status FROM transfer_history WHERE transfer_id='t_recv_a'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        s, "failed",
        "matching receive without staging files is marked failed"
    );
}

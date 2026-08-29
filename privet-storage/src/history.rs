
use crate::error::StorageError;
use rusqlite::OptionalExtension;

#[derive(Copy, Clone)]
pub enum TransferDirection {
    Send,
    Receive,
}
impl TransferDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Receive => "receive",
        }
    }
}

#[derive(Copy, Clone)]
pub enum TransferStatus {
    Completed,
    Cancelled,
    Failed,
    Partial,
}
impl TransferStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Partial => "partial",
        }
    }
}

pub struct NewTransfer<'a> {
    pub transfer_id: &'a str,
    pub direction: TransferDirection,
    pub peer_device_fingerprint: Option<&'a str>,
    pub peer_name: Option<&'a str>,
    pub root_name: Option<&'a str>,
    pub file_count: u64,
    pub total_bytes: u64,
    pub status: TransferStatus,
    pub started_ts: i64,
    pub save_dir: Option<&'a str>,
    pub send_intent: &'a str,
}

pub struct FileRow<'a> {
    pub file_id: &'a str,
    pub relative_path: &'a str,
    pub size: u64,
    pub hash_type: Option<&'a str>,
    pub hash_value: Option<&'a str>,
    pub status: &'a str,
    pub source_path: Option<&'a str>,
}

pub fn insert_history(conn: &rusqlite::Connection, t: &NewTransfer) -> Result<(), StorageError> {
    // storage-layer path guard before DB insert
    let guarded_root = match t.root_name {
        Some(rn) => crate::path_guard::guard_root_name(rn)?,
        None => None,
    };
    let root_name = guarded_root.as_deref();
    conn.execute(
        "INSERT INTO transfer_history
           (transfer_id, direction, peer_device_fingerprint, peer_name, root_name, file_count,
            total_bytes, status, started_ts, save_dir, send_intent)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            t.transfer_id,
            t.direction.as_str(),
            t.peer_device_fingerprint,
            t.peer_name,
            root_name,
            t.file_count as i64,
            t.total_bytes as i64,
            t.status.as_str(),
            t.started_ts,
            t.save_dir,
            t.send_intent
        ],
    )?;
    Ok(())
}

pub fn complete_history(
    conn: &rusqlite::Connection,
    transfer_id: &str,
    files: &[FileRow],
    finished_ts: i64,
) -> Result<(), StorageError> {
    // storage-layer path guard before DB insert
    for f in files {
        let _ = crate::path_guard::guard_relative_path(f.relative_path)?;
    }
    let tx = conn.unchecked_transaction()?;
    let res = (|| -> Result<(), rusqlite::Error> {
        tx.execute(
            "UPDATE transfer_history SET status='completed', finished_ts=?1 WHERE transfer_id=?2",
            rusqlite::params![finished_ts, transfer_id],
        )?;
        for f in files {
            // A send inserts its file rows at start time (insert_send_files) so
            // a partial/interrupted send still lists its files; upgrade those
            // pre-existing rows instead of colliding on the primary key. On the
            // receive path no rows exist yet, so the upsert is a plain insert.
            tx.execute(
                "INSERT INTO transfer_files (transfer_id, file_id, relative_path, size, hash_type, hash_value, status, source_path)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(transfer_id, file_id) DO UPDATE SET
                   status=excluded.status,
                   size=excluded.size,
                   hash_type=excluded.hash_type,
                   hash_value=excluded.hash_value,
                   source_path=excluded.source_path",
                rusqlite::params![
                    transfer_id,
                    f.file_id,
                    f.relative_path,
                    f.size as i64,
                    f.hash_type,
                    f.hash_value,
                    f.status,
                    f.source_path,
                ],
            )?;
        }
        Ok(())
    })();
    match res {
        Ok(()) => tx.commit().map_err(Into::into),
        Err(e) => {
            let _ = tx.rollback();
            Err(e.into())
        }
    }
}

/// Inserts the per-file rows at transfer start time, so a partial/interrupted
/// transfer still lists its files in history. On the send side this happens
/// when the transfer is prepared (rows carry the source paths a resend needs);
/// on the receive side it happens once the FileSetBatch manifest is known
/// (source_path is None). Rows start at the "failed" sentinel;
/// `complete_history` upgrades them to "completed" on success. Idempotent per
/// (transfer_id, file_id).
pub fn insert_send_files(
    conn: &rusqlite::Connection,
    transfer_id: &str,
    files: &[FileRow],
) -> Result<(), StorageError> {
    for f in files {
        let _ = crate::path_guard::guard_relative_path(f.relative_path)?;
    }
    let tx = conn.unchecked_transaction()?;
    let res = (|| -> Result<(), rusqlite::Error> {
        for f in files {
            tx.execute(
                "INSERT OR REPLACE INTO transfer_files
                   (transfer_id, file_id, relative_path, size, hash_type, hash_value, status, source_path)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    transfer_id,
                    f.file_id,
                    f.relative_path,
                    f.size as i64,
                    f.hash_type,
                    f.hash_value,
                    "failed",
                    f.source_path,
                ],
            )?;
        }
        Ok(())
    })();
    match res {
        Ok(()) => tx.commit().map_err(Into::into),
        Err(e) => {
            let _ = tx.rollback();
            Err(e.into())
        }
    }
}

pub fn clear_history(conn: &rusqlite::Connection) -> Result<(), StorageError> {
    conn.execute("DELETE FROM transfer_history", [])?;
    Ok(())
}

pub fn delete_history_entry(
    conn: &rusqlite::Connection,
    transfer_id: &str,
) -> Result<(), StorageError> {
    conn.execute(
        "DELETE FROM transfer_history WHERE transfer_id=?1",
        rusqlite::params![transfer_id],
    )?;
    Ok(())
}

pub fn clear_history_by_peer(
    conn: &rusqlite::Connection,
    device_fingerprint: &str,
) -> Result<(), StorageError> {
    conn.execute(
        "DELETE FROM transfer_history WHERE peer_device_fingerprint=?1",
        rusqlite::params![device_fingerprint],
    )?;
    Ok(())
}

pub fn vacuum_after_clear(conn: &rusqlite::Connection) -> Result<(), StorageError> {
    conn.execute_batch("PRAGMA incremental_vacuum")?;
    Ok(())
}

pub fn update_send_counts(
    conn: &rusqlite::Connection,
    transfer_id: &str,
    file_count: u64,
    total_bytes: u64,
    root_name: Option<&str>,
) -> Result<(), StorageError> {
    let guarded_root = match root_name {
        Some(rn) => crate::path_guard::guard_root_name(rn)?,
        None => None,
    };
    conn.execute(
        "UPDATE transfer_history SET file_count=?1, total_bytes=?2, root_name=?3 WHERE transfer_id=?4",
        rusqlite::params![file_count as i64, total_bytes as i64, guarded_root.as_deref(), transfer_id],
    )?;
    Ok(())
}

pub fn mark_partial(conn: &rusqlite::Connection, transfer_id: &str) -> Result<(), StorageError> {
    conn.execute(
        "UPDATE transfer_history SET status='partial' WHERE transfer_id=?1",
        rusqlite::params![transfer_id],
    )?;
    Ok(())
}

pub struct SendIntentRow {
    pub transfer_id: String,
    pub direction: String,
    pub status: String,
    pub peer_device_fingerprint: Option<String>,
    pub peer_name: Option<String>,
    pub root_name: Option<String>,
    pub file_count: u64,
    pub total_bytes: u64,
    pub send_intent: Option<String>,
}

pub fn get_send_intent_row(
    conn: &rusqlite::Connection,
    transfer_id: &str,
) -> Result<Option<SendIntentRow>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT transfer_id, direction, status, peer_device_fingerprint, peer_name, root_name,
                file_count, total_bytes, send_intent
         FROM transfer_history WHERE transfer_id=?1",
    )?;
    let mut rows = stmt.query_map(rusqlite::params![transfer_id], |r| {
        Ok(SendIntentRow {
            transfer_id: r.get(0)?,
            direction: r.get(1)?,
            status: r.get(2)?,
            peer_device_fingerprint: r.get(3)?,
            peer_name: r.get(4)?,
            root_name: r.get(5)?,
            file_count: r.get::<_, i64>(6)? as u64,
            total_bytes: r.get::<_, i64>(7)? as u64,
            send_intent: r.get(8)?,
        })
    })?;
    match rows.next() {
        Some(Ok(row)) => Ok(Some(row)),
        Some(Err(e)) => Err(e.into()),
        None => Ok(None),
    }
}

pub fn mark_failed(
    conn: &rusqlite::Connection,
    transfer_id: &str,
    error: &str,
) -> Result<(), StorageError> {
    let finished_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    conn.execute(
        "UPDATE transfer_history SET status='failed', error=?1, finished_ts=?3 WHERE transfer_id=?2",
        rusqlite::params![error, transfer_id, finished_ts],
    )?;
    Ok(())
}

pub struct HistoryRow {
    pub transfer_id: String,
    pub direction: String,
    pub peer_device_fingerprint: Option<String>,
    pub peer_name: Option<String>,
    pub root_name: Option<String>,
    pub file_count: u64,
    pub total_bytes: u64,
    pub status: String,
    pub started_ts: i64,
    pub finished_ts: Option<i64>,
}

pub fn list_history(
    conn: &rusqlite::Connection,
    peer: Option<&str>,
    limit: i64,
) -> Result<Vec<HistoryRow>, StorageError> {
    let sql = if peer.is_some() {
        "SELECT transfer_id, direction, peer_device_fingerprint, peer_name, root_name, file_count,
                total_bytes, status, started_ts, finished_ts
         FROM transfer_history WHERE peer_device_fingerprint=?1
         ORDER BY started_ts DESC, transfer_id DESC LIMIT ?2"
    } else {
        "SELECT transfer_id, direction, peer_device_fingerprint, peer_name, root_name, file_count,
                total_bytes, status, started_ts, finished_ts
         FROM transfer_history
         ORDER BY started_ts DESC, transfer_id DESC LIMIT ?1"
    };
    let mut stmt = conn.prepare(sql)?;
    let map = |r: &rusqlite::Row| {
        Ok(HistoryRow {
            transfer_id: r.get(0)?,
            direction: r.get(1)?,
            peer_device_fingerprint: r.get(2)?,
            peer_name: r.get(3)?,
            root_name: r.get(4)?,
            file_count: r.get::<_, i64>(5)? as u64,
            total_bytes: r.get::<_, i64>(6)? as u64,
            status: r.get(7)?,
            started_ts: r.get(8)?,
            finished_ts: r.get(9)?,
        })
    };
    let rows = if let Some(p) = peer {
        stmt.query_map(rusqlite::params![p, limit], map)?
    } else {
        stmt.query_map(rusqlite::params![limit], map)?
    };
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

pub struct HistoryFileRow {
    pub relative_path: String,
    pub source_path: Option<String>,
    pub size: u64,
    pub status: String,
}

pub struct HistoryDetailRow {
    pub transfer_id: String,
    pub direction: String,
    pub peer_device_fingerprint: Option<String>,
    pub peer_name: Option<String>,
    pub root_name: Option<String>,
    pub status: String,
    pub started_ts: i64,
    pub finished_ts: Option<i64>,
    pub save_dir: Option<String>,
    pub files: Vec<HistoryFileRow>,
}

pub fn get_history_detail(
    conn: &rusqlite::Connection,
    transfer_id: &str,
) -> Result<Option<HistoryDetailRow>, StorageError> {
    let summary = conn
        .query_row(
            "SELECT transfer_id, direction, peer_device_fingerprint, peer_name, root_name, status,
                    started_ts, finished_ts, save_dir
             FROM transfer_history WHERE transfer_id=?1",
            rusqlite::params![transfer_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<String>>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, Option<i64>>(7)?,
                    r.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()?;
    let Some((
        transfer_id,
        direction,
        peer_device_fingerprint,
        peer_name,
        root_name,
        status,
        started_ts,
        finished_ts,
        save_dir,
    )) = summary
    else {
        return Ok(None);
    };

    let mut stmt = conn.prepare(
        "SELECT relative_path, source_path, size, status FROM transfer_files
         WHERE transfer_id=?1 ORDER BY relative_path, file_id",
    )?;
    let files = stmt
        .query_map(rusqlite::params![transfer_id], |r| {
            Ok(HistoryFileRow {
                relative_path: r.get(0)?,
                source_path: r.get(1)?,
                size: r.get::<_, i64>(2)? as u64,
                status: r.get(3)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(Some(HistoryDetailRow {
        transfer_id,
        direction,
        peer_device_fingerprint,
        peer_name,
        root_name,
        status,
        started_ts,
        finished_ts,
        save_dir,
        files,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> rusqlite::Connection {
        let conn = crate::db::open_in_memory().unwrap();
        crate::migration::run_migrations(&conn, crate::migration::MIGRATIONS).unwrap();
        conn
    }

    fn new_xfer<'a>(id: &'a str, peer: Option<&'a str>) -> NewTransfer<'a> {
        NewTransfer {
            transfer_id: id,
            direction: TransferDirection::Receive,
            peer_device_fingerprint: peer,
            peer_name: Some("peer"),
            root_name: None,
            file_count: 0,
            total_bytes: 0,
            status: TransferStatus::Partial,
            started_ts: 1,
            save_dir: Some("/tmp/s"),
            send_intent: "{}"
        }
    }

    #[test]
    fn complete_history_inserts_files_atomically() {
        let conn = db();
        insert_history(&conn, &new_xfer("t1", None)).unwrap();
        let files = [
            FileRow {
                file_id: "f1",
                relative_path: "a.txt",
                size: 10,
                hash_type: "blake3".into(),
                hash_value: Some("dead"),
                status: "completed",
                source_path: None,
            },
            FileRow {
                file_id: "f2",
                relative_path: "b.txt",
                size: 20,
                hash_type: "blake3".into(),
                hash_value: None,
                status: "failed",
                source_path: None,
            },
        ];
        complete_history(&conn, "t1", &files, 999).unwrap();
        let (status, fin): (String, i64) = conn
            .query_row(
                "SELECT status, finished_ts FROM transfer_history WHERE transfer_id='t1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "completed");
        assert_eq!(fin, 999);
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM transfer_files WHERE transfer_id='t1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn complete_history_rolls_back_on_mid_failure() {
        let conn = db();
        insert_history(&conn, &new_xfer("t1", None)).unwrap();
        // The second row violates the transfer_files status CHECK after the
        // first insert succeeds, so the whole write must roll back (the old
        // duplicate-(transfer_id, file_id) trigger is now a harmless upsert).
        let files = [
            FileRow {
                file_id: "f1",
                relative_path: "a.txt",
                size: 10,
                hash_type: "blake3".into(),
                hash_value: None,
                status: "completed",
                source_path: None,
            },
            FileRow {
                file_id: "f2",
                relative_path: "b.txt",
                size: 20,
                hash_type: "blake3".into(),
                hash_value: None,
                status: "boom",
                source_path: None,
            },
        ];
        assert!(complete_history(&conn, "t1", &files, 999).is_err());
        let status: String = conn
            .query_row(
                "SELECT status FROM transfer_history WHERE transfer_id='t1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "partial");
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM transfer_files WHERE transfer_id='t1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn insert_send_files_persists_source_paths_for_partial_send() {
        let conn = db();
        insert_history(&conn, &new_xfer("t1", None)).unwrap();
        // Send start: file rows carry source paths before the transfer ends, so
        // a partial/interrupted send still lists its files for a later resend.
        insert_send_files(
            &conn,
            "t1",
            &[FileRow {
                file_id: "f1",
                relative_path: "a.txt",
                size: 10,
                hash_type: "blake3".into(),
                hash_value: Some("dead"),
                status: "failed",
                source_path: Some("/src/a.txt"),
            }],
        )
        .unwrap();
        let detail = get_history_detail(&conn, "t1").unwrap().unwrap();
        assert_eq!(detail.status, "partial");
        assert_eq!(detail.files.len(), 1);
        assert_eq!(detail.files[0].source_path.as_deref(), Some("/src/a.txt"));
        assert_eq!(detail.files[0].status, "failed");

        // Completion upgrades the pre-inserted rows rather than colliding on
        // the (transfer_id, file_id) primary key.
        complete_history(
            &conn,
            "t1",
            &[FileRow {
                file_id: "f1",
                relative_path: "a.txt",
                size: 10,
                hash_type: "blake3".into(),
                hash_value: Some("dead"),
                status: "completed",
                source_path: Some("/src/a.txt"),
            }],
            999,
        )
        .unwrap();
        let detail = get_history_detail(&conn, "t1").unwrap().unwrap();
        assert_eq!(detail.status, "completed");
        assert_eq!(detail.files.len(), 1);
        assert_eq!(detail.files[0].status, "completed");
        assert_eq!(detail.files[0].source_path.as_deref(), Some("/src/a.txt"));
    }

    #[test]
    fn clear_history_wipes_both_tables() {
        let conn = db();
        insert_history(&conn, &new_xfer("t1", None)).unwrap();
        complete_history(
            &conn,
            "t1",
            &[FileRow {
                file_id: "f1",
                relative_path: "a",
                size: 1,
                hash_type: "blake3".into(),
                hash_value: None,
                status: "completed",
                source_path: None,
            }],
            1,
        )
        .unwrap();
        clear_history(&conn).unwrap();
        let h: i64 = conn
            .query_row("SELECT COUNT(*) FROM transfer_history", [], |r| r.get(0))
            .unwrap();
        let f: i64 = conn
            .query_row("SELECT COUNT(*) FROM transfer_files", [], |r| r.get(0))
            .unwrap();
        assert_eq!((h, f), (0, 0));
    }

    #[test]
    fn clear_history_by_peer_wipes_only_that_peer() {
        let conn = db();
        for d in ["d1", "d2"] {
            conn.execute(
                "INSERT INTO trust_store(device_fingerprint,peer_spki,peer_device_name,first_paired_ts,last_seen_ts) VALUES(?1,x'00','n',1,1)",
                rusqlite::params![d],
            )
            .unwrap();
        }
        insert_history(&conn, &new_xfer("t1", Some("d1"))).unwrap();
        insert_history(&conn, &new_xfer("t2", Some("d2"))).unwrap();
        clear_history_by_peer(&conn, "d1").unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM transfer_history", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn mark_partial_sets_status() {
        let conn = db();
        insert_history(&conn, &new_xfer("t1", None)).unwrap();
        mark_partial(&conn, "t1").unwrap();
        let s: String = conn
            .query_row(
                "SELECT status FROM transfer_history WHERE transfer_id='t1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(s, "partial");
    }

    #[test]
    fn mark_failed_sets_status_and_error() {
        let conn = db();
        insert_history(&conn, &new_xfer("t1", None)).unwrap();
        mark_partial(&conn, "t1").unwrap();
        mark_failed(&conn, "t1", "no part files on disk").unwrap();
        let (s, e): (String, String) = conn
            .query_row(
                "SELECT status, COALESCE(error,'') FROM transfer_history WHERE transfer_id='t1'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(s, "failed");
        assert_eq!(e, "no part files on disk");
    }

    #[test]
    fn list_history_orders_desc_and_filters_peer_and_limit() {
        let conn = db();
        for d in &["d1", "d2"] {
            conn.execute(
                "INSERT INTO trust_store(device_fingerprint,peer_spki,peer_device_name,first_paired_ts,last_seen_ts) VALUES(?1,x'00','n',1,1)",
                rusqlite::params![d],
            )
            .unwrap();
        }
        insert_history(&conn, &new_xfer("t1", Some("d1"))).unwrap();
        insert_history(&conn, &new_xfer("t2", Some("d2"))).unwrap();
        insert_history(&conn, &new_xfer("t3", Some("d1"))).unwrap();
        let all = list_history(&conn, None, 100).unwrap();
        assert_eq!(all.len(), 3);
        let d1 = list_history(&conn, Some("d1"), 100).unwrap();
        assert_eq!(d1.len(), 2);
        assert!(d1.iter().all(|r| r.peer_device_fingerprint.as_deref() == Some("d1")));
        let lim = list_history(&conn, None, 2).unwrap();
        assert_eq!(lim.len(), 2);
        let row = &all[0];
        assert!(!row.transfer_id.is_empty());
        assert_eq!(row.direction, "receive");
        assert_eq!(row.status, "partial");
    }

    #[test]
    fn complete_history_persists_source_path() {
        let conn = db();
        insert_history(&conn, &new_xfer("t1", None)).unwrap();
        let files = [
            FileRow {
                file_id: "f1",
                relative_path: "a.txt",
                size: 10,
                hash_type: "blake3".into(),
                hash_value: Some("dead"),
                status: "completed",
                source_path: Some("/home/u/docs/a.txt"),
            },
        ];
        complete_history(&conn, "t1", &files, 999).unwrap();
        let source_path: Option<String> = conn
            .query_row(
                "SELECT source_path FROM transfer_files WHERE transfer_id='t1' AND file_id='f1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(source_path.as_deref(), Some("/home/u/docs/a.txt"));
    }

    #[test]
    fn delete_history_entry_removes_transfer_and_files() {
        let conn = db();
        insert_history(&conn, &new_xfer("t1", None)).unwrap();
        complete_history(
            &conn,
            "t1",
            &[FileRow {
                file_id: "f1",
                relative_path: "a",
                size: 1,
                hash_type: "blake3".into(),
                hash_value: None,
                status: "completed",
                source_path: None,
            }],
            1,
        )
        .unwrap();
        delete_history_entry(&conn, "t1").unwrap();
        let h: i64 = conn
            .query_row("SELECT COUNT(*) FROM transfer_history", [], |r| r.get(0))
            .unwrap();
        let f: i64 = conn
            .query_row("SELECT COUNT(*) FROM transfer_files", [], |r| r.get(0))
            .unwrap();
        assert_eq!((h, f), (0, 0));
        // Deleting a missing id is a no-op, not an error.
        assert!(delete_history_entry(&conn, "does-not-exist").is_ok());
    }

    #[test]
    fn get_history_detail_returns_summary_and_files() {
        let conn = db();
        // seed a completed receive with save_dir and two files
        let mut t = new_xfer("t1", None);
        t.save_dir = Some("/tmp/s");
        t.root_name = Some("docs");
        insert_history(&conn, &t).unwrap();
        complete_history(
            &conn,
            "t1",
            &[
                FileRow {
                    file_id: "f1",
                    relative_path: "a.txt",
                    size: 10,
                    hash_type: "blake3".into(),
                    hash_value: Some("h1"),
                    status: "completed",
                    source_path: None,
                },
                FileRow {
                    file_id: "f2",
                    relative_path: "sub/b.txt",
                    size: 20,
                    hash_type: "blake3".into(),
                    hash_value: Some("h2"),
                    status: "completed",
                    source_path: None,
                },
            ],
            999,
        )
        .unwrap();

        let row = get_history_detail(&conn, "t1").unwrap().unwrap();
        assert_eq!(row.transfer_id, "t1");
        assert_eq!(row.direction, "receive");
        assert_eq!(row.save_dir.as_deref(), Some("/tmp/s"));
        assert_eq!(row.root_name.as_deref(), Some("docs"));
        assert_eq!(row.status, "completed");
        assert_eq!(row.files.len(), 2);
        assert_eq!(row.files[0].relative_path, "a.txt");
        assert_eq!(row.files[0].size, 10);
        assert_eq!(row.files[1].relative_path, "sub/b.txt");

        assert!(get_history_detail(&conn, "missing").unwrap().is_none());
    }
}

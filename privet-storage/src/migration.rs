
use crate::error::StorageError;

pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub sql: &'static str,
}

pub fn run_migrations(
    conn: &rusqlite::Connection,
    migrations: &[Migration],
) -> Result<(), StorageError> {
    ensure_schema_version_table(conn)?;
    let current: Option<i64> =
        conn.query_row("SELECT MAX(version) FROM schema_version", [], |r| {
            r.get::<_, Option<i64>>(0)
        })?;
    let current = current.unwrap_or(0) as u32;

    for m in migrations.iter().filter(|m| m.version > current) {
        let tx = conn.unchecked_transaction()?;
        let res = (|| -> Result<(), rusqlite::Error> {
            tx.execute_batch(m.sql)?;
            tx.execute(
                "INSERT INTO schema_version (version, applied_ts) VALUES (?1, ?2)",
                rusqlite::params![m.version as i64, unix_now_secs()],
            )?;
            Ok(())
        })();
        match res {
            Ok(()) => tx.commit()?,
            Err(e) => {
                let _ = tx.rollback();
                return Err(StorageError::Migration {
                    version: m.version,
                    reason: e.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn ensure_schema_version_table(conn: &rusqlite::Connection) -> Result<(), StorageError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
           version    INTEGER PRIMARY KEY,
           applied_ts INTEGER NOT NULL
         );",
    )?;
    Ok(())
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

use crate::schema_v1::V1_SQL;

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "baseline",
        sql: V1_SQL,
    }
];

pub fn open_and_migrate(
    path: impl AsRef<std::path::Path>,
) -> Result<rusqlite::Connection, StorageError> {
    let conn = crate::db::open(path)?;
    run_migrations(&conn, MIGRATIONS)?;
    Ok(conn)
}

//! DB 连接与 PRAGMA + 桌面默认路径。

use std::path::{Path, PathBuf};

use crate::constants::BUSY_TIMEOUT_MS;
use crate::error::StorageError;

pub fn open(path: impl AsRef<Path>) -> Result<rusqlite::Connection, StorageError> {
    let conn = rusqlite::Connection::open(path.as_ref())?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

/// 内存 DB + 全 PRAGMA（测试用）。`foreign_keys=ON` 使 CASCADE/SET NULL 在测试中生效。
pub fn open_in_memory() -> Result<rusqlite::Connection, StorageError> {
    let conn = rusqlite::Connection::open_in_memory()?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

fn apply_pragmas(conn: &rusqlite::Connection) -> Result<(), StorageError> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "busy_timeout", BUSY_TIMEOUT_MS)?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    Ok(())
}

/// 桌面平台默认 DB 目录。无 fs 副作用（仅读 env，不建目录）。
pub fn default_db_dir() -> PathBuf {
    dirs::data_dir().unwrap_or_default().join("privet")
}

/// 桌面平台默认 DB 路径。建 `privet/` 目录。Android 由调用方传显式路径。
pub fn default_db_path() -> Result<PathBuf, StorageError> {
    let dir = default_db_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("privet.db"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_sets_pragmas() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let conn = open(tmp.path()).unwrap();
        let jm: String = conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(jm.to_lowercase(), "wal");
        let syn: i64 = conn
            .pragma_query_value(None, "synchronous", |r| r.get(0))
            .unwrap();
        assert_eq!(syn, 1); // 1 = NORMAL
        let bt: i64 = conn
            .pragma_query_value(None, "busy_timeout", |r| r.get(0))
            .unwrap();
        assert_eq!(bt, BUSY_TIMEOUT_MS as i64);
        let fk: i64 = conn
            .pragma_query_value(None, "foreign_keys", |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1);
        let ts: i64 = conn
            .pragma_query_value(None, "temp_store", |r| r.get(0))
            .unwrap();
        assert_eq!(ts, 2); // 2 = MEMORY
    }

    #[test]
    fn default_db_dir_under_privet() {
        // 仅查路径名，无 fs 副作用（不创建用户数据目录）。
        let p = default_db_dir();
        assert!(p.ends_with("privet"));
    }
}

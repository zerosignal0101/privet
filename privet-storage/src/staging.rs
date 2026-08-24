//! staging 目录生命周期 + 孤儿对账

use std::path::{Path, PathBuf};

use crate::constants::{PART_META_SUFFIX, PART_SUFFIX, STAGING_DIR_NAME};
use crate::error::StorageError;

/// 完成：rename `.part` -> 最终（终态已存在 -> InvalidState；碰撞策略由 P4 解析后传最终路径）+ 删 `.part.meta`。
pub fn finalize_part_file(part_path: &Path, final_path: &Path) -> Result<(), StorageError> {
    if final_path.exists() {
        return Err(StorageError::InvalidState(format!(
            "final path already exists: {}",
            final_path.display()
        )));
    }
    if let Some(parent) = final_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // crash durability: fsync .part before rename
    {
        let pf = std::fs::OpenOptions::new().write(true).open(part_path)?;
        pf.sync_all()?;
    }
    std::fs::rename(part_path, final_path)?;
    crate::sidecar::fsync_parent(final_path)?; // parent dir fsync after rename
    let meta = meta_path_for_part(part_path);
    if meta.exists() {
        std::fs::remove_file(&meta)?;
    }
    Ok(())
}

/// 取消/丢弃：删 `.part` + `.part.meta`（保留已落地文件）。容忍缺失。
pub fn delete_part_and_meta(part_path: &Path) -> Result<(), StorageError> {
    let _ = std::fs::remove_file(part_path);
    let _ = std::fs::remove_file(meta_path_for_part(part_path));
    Ok(())
}

/// 自底向上 rmdir 空目录（Q2）：从 transfer_dir 起向上删空目录至其父（不含父）。
pub fn cleanup_staging_dir(transfer_dir: &Path) -> Result<(), StorageError> {
    remove_empty_dirs_up(transfer_dir, transfer_dir.parent());
    Ok(())
}

/// 启动孤儿对账
/// 1. 文件系统对账（仅当 .privet 存在）：清理无伴 .part/.part.meta、删空 transfer 目录、空 .privet 删。
/// 2. DB 对账（无条件执行）：status='partial' 但 staging 无文件 -> mark_failed（即便 .privet 不存在）。
pub fn orphan_reconcile(save_dir: &Path, conn: &rusqlite::Connection) -> Result<(), StorageError> {
    let privet_dir = save_dir.join(STAGING_DIR_NAME);

    if privet_dir.exists() {
        for entry in std::fs::read_dir(&privet_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let transfer_dir = entry.path();
            let has_any = reconcile_transfer_dir(&transfer_dir)?;
            if !has_any {
                let _ = std::fs::remove_dir(&transfer_dir);
            }
        }
        if is_dir_empty(&privet_dir)? {
            let _ = std::fs::remove_dir(&privet_dir);
        }
    }

    // 无条件：DB partial 但 staging 无文件 -> mark_failed（即便 .privet 不存在）。
    //        仅 reconcile direction='receive' 且 save_dir 匹配的 partial 行，
    //        SEND 和其他 save_dir 的 RECEIVE 不得被标记为 failed。
    for tid in list_partial_receives(conn, save_dir)? {
        let tdir = privet_dir.join(&tid);
        let has = tdir.exists() && has_any_part(&tdir)?;
        if !has {
            crate::history::mark_failed(conn, &tid, "orphan: no part files on disk")?;
        }
    }
    Ok(())
}

/// `.part` 路径 -> `.part.meta` 路径：`a/b.txt.part` -> `a/b.txt.part.meta`。
fn meta_path_for_part(part_path: &Path) -> PathBuf {
    let base = part_path.with_extension("");
    let mut correct = base.as_os_str().to_owned();
    correct.push(PART_META_SUFFIX);
    PathBuf::from(correct)
}

/// `.part.meta` 路径 -> `.part` 路径：去 `.part.meta` 后缀追加 `.part`。
fn part_file_of_meta(meta: &Path) -> PathBuf {
    let s = meta.to_string_lossy();
    let base = s.trim_end_matches(PART_META_SUFFIX);
    let mut p = base.to_string();
    p.push_str(PART_SUFFIX);
    PathBuf::from(p)
}

fn reconcile_transfer_dir(transfer_dir: &Path) -> Result<bool, StorageError> {
    let mut has_any = false;
    for entry in walk_files(transfer_dir)? {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(PART_META_SUFFIX) {
            let part_p = part_file_of_meta(&entry.path());
            if !part_p.exists() {
                let _ = std::fs::remove_file(entry.path());
            } else {
                has_any = true;
            }
        } else if name.ends_with(PART_SUFFIX) {
            let meta = meta_path_for_part(&entry.path());
            if !meta.exists() {
                let _ = std::fs::remove_file(entry.path());
            } else {
                has_any = true;
            }
        }
    }
    remove_empty_subdirs(transfer_dir)?;
    Ok(has_any)
}

fn walk_files(dir: &Path) -> Result<Vec<std::fs::DirEntry>, StorageError> {
    let mut out = Vec::new();
    walk_files_inner(dir, &mut out)?;
    Ok(out)
}

fn walk_files_inner(dir: &Path, out: &mut Vec<std::fs::DirEntry>) -> Result<(), StorageError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_files_inner(&entry.path(), out)?;
        } else {
            out.push(entry);
        }
    }
    Ok(())
}

/// 后序递归：先清子目录，再 rmdir 空（空则成）。
fn remove_empty_subdirs(top: &Path) -> Result<(), StorageError> {
    for entry in std::fs::read_dir(top)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remove_empty_subdirs(&entry.path())?;
            if is_dir_empty(&entry.path())? {
                let _ = std::fs::remove_dir(entry.path());
            }
        }
    }
    Ok(())
}

fn remove_empty_dirs_up(start: &Path, stop: Option<&Path>) {
    let mut cur = start.to_path_buf();
    while let Some(parent) = cur.parent() {
        if Some(parent) == stop {
            break;
        }
        if is_dir_empty_ok(&cur) {
            if std::fs::remove_dir(&cur).is_err() {
                break;
            }
        } else {
            break;
        }
        cur = parent.to_path_buf();
    }
}

fn is_dir_empty(p: &Path) -> Result<bool, StorageError> {
    Ok(std::fs::read_dir(p)?.next().is_none())
}

fn is_dir_empty_ok(p: &Path) -> bool {
    std::fs::read_dir(p)
        .map(|mut it| it.next().is_none())
        .unwrap_or(false)
}

fn has_any_part(transfer_dir: &Path) -> Result<bool, StorageError> {
    for f in walk_files(transfer_dir)? {
        let n = f.file_name().to_string_lossy().to_string();
        if n.ends_with(PART_SUFFIX) || n.ends_with(PART_META_SUFFIX) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 列出 save_dir 下 direction='receive' 且 status='partial' 的 transfer（孤儿对账用）。
/// SEND 和其他 save_dir 的 RECEIVE 被跳过，避免误标记为 failed。
fn list_partial_receives(
    conn: &rusqlite::Connection,
    save_dir: &Path,
) -> Result<Vec<String>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT transfer_id FROM transfer_history
         WHERE status='partial' AND direction='receive' AND save_dir=?1",
    )?;
    let rows = stmt.query_map([save_dir.to_str().unwrap_or("")], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidecar::{part_meta_path, part_path};

    fn db() -> rusqlite::Connection {
        let conn = crate::db::open_in_memory().unwrap();
        crate::migration::run_migrations(&conn, crate::migration::MIGRATIONS).unwrap();
        conn
    }

    fn write_file(p: &Path, data: &[u8]) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    #[test]
    fn finalize_renames_part_and_deletes_meta() {
        let dir = tempfile::tempdir().unwrap();
        let save = dir.path();
        let part = part_path(save, "t1", "a.txt").unwrap();
        let final_p = dir.path().join("out").join("a.txt");
        write_file(&part, b"hello");
        write_file(&meta_path_for_part(&part), b"meta");
        finalize_part_file(&part, &final_p).unwrap();
        assert!(final_p.exists());
        assert!(!part.exists());
        assert!(!meta_path_for_part(&part).exists());
    }

    #[test]
    fn finalize_rejects_existing_final() {
        let dir = tempfile::tempdir().unwrap();
        let save = dir.path();
        let part = part_path(save, "t1", "a.txt").unwrap();
        let final_p = dir.path().join("a.txt");
        write_file(&part, b"hello");
        write_file(&final_p, b"existing");
        let err = finalize_part_file(&part, &final_p).unwrap_err();
        assert!(matches!(err, StorageError::InvalidState(_)));
    }

    #[test]
    fn delete_part_and_meta_removes_both() {
        let dir = tempfile::tempdir().unwrap();
        let save = dir.path();
        let part = part_path(save, "t1", "a.txt").unwrap();
        write_file(&part, b"hello");
        write_file(&meta_path_for_part(&part), b"meta");
        delete_part_and_meta(&part).unwrap();
        assert!(!part.exists());
        assert!(!meta_path_for_part(&part).exists());
    }

    #[test]
    fn orphan_part_without_meta_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        let save = dir.path();
        let part = part_path(save, "t1", "a.txt").unwrap();
        write_file(&part, b"hello");
        orphan_reconcile(save, &db()).unwrap();
        assert!(!part.exists());
    }

    #[test]
    fn orphan_meta_without_part_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        let save = dir.path();
        let meta = part_meta_path(save, "t1", "a.txt").unwrap();
        write_file(&meta, b"meta");
        orphan_reconcile(save, &db()).unwrap();
        assert!(!meta.exists());
    }

    #[test]
    fn orphan_empty_transfer_and_privet_dirs_removed() {
        let dir = tempfile::tempdir().unwrap();
        let save = dir.path();
        let tdir = save.join(STAGING_DIR_NAME).join("t1");
        std::fs::create_dir_all(&tdir).unwrap();
        orphan_reconcile(save, &db()).unwrap();
        assert!(!tdir.exists());
        assert!(!save.join(STAGING_DIR_NAME).exists());
    }

    #[test]
    fn orphan_db_partial_but_no_files_marks_failed() {
        let conn = db();
        conn.execute(
            "INSERT INTO transfer_history(transfer_id,direction,file_count,total_bytes,status,started_ts,save_dir,send_intent)
             VALUES('t_orphan','receive',1,10,'partial',1,'/tmp/x_nonexistent_save_dir','{}')",
            [],
        )
        .unwrap();
        orphan_reconcile(Path::new("/tmp/x_nonexistent_save_dir"), &conn).unwrap();
        let s: String = conn
            .query_row(
                "SELECT status FROM transfer_history WHERE transfer_id='t_orphan'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(s, "failed");
    }
}

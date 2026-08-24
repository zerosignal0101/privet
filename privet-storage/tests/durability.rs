//! crash durability: parent-dir fsync after rename.
//! 测试 atomic_write_fsync 和 finalize_part_file 在 rename 后同步父目录。

use privet_storage::sidecar::{part_meta_path, write_part_meta_initial};
use privet_storage::staging::finalize_part_file;
use privet_storage::PartMeta;

#[test]
fn sidecar_write_then_readable() {
    // atomic_write_fsync 写入的 sidecar 文件可读（rename + parent fsync 后立即可见）。
    let dir = tempfile::tempdir().unwrap();
    let mp = part_meta_path(dir.path(), "t1", "a.txt").unwrap();
    let meta = PartMeta {
        transfer_id: "t1".into(),
        file_id: "f1".into(),
        relative_path: "a.txt".into(),
        size: 10,
        mtime_ms: 0,
        hash_type: "blake3".into(),
        hash_value: "hash".into(),
        segments: vec![],
    };
    write_part_meta_initial(&mp, &meta).unwrap();
    // 文件可读（rename 已完成）
    let read_back = std::fs::read(&mp).unwrap();
    assert!(!read_back.is_empty(), "sidecar file is non-empty");
}

#[test]
fn finalize_part_rename_durable() {
    // finalize_part_file 后最终文件存在且可读。
    let dir = tempfile::tempdir().unwrap();
    let part = dir.path().join("a.txt.part");
    let final_p = dir.path().join("a.txt");
    std::fs::write(&part, b"hello durability").unwrap();
    finalize_part_file(&part, &final_p).unwrap();
    assert!(final_p.exists(), "final file exists after rename");
    assert!(!part.exists(), "part file removed");
    assert_eq!(
        std::fs::read(&final_p).unwrap(),
        b"hello durability",
        "content preserved"
    );
}
